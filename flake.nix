{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, fenix }:
    let
      forAllSystems = fn:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: fn {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            };
            inherit system;
          });
    in {
      packages = forAllSystems ({ pkgs, system }:
        let
          rustNightly = pkgs.rust-bin.nightly.latest.default.override {
            extensions = [ "rust-src" ];
          };

          # Vendor workspace deps (userspace crates)
          workspaceVendor = pkgs.rustPlatform.fetchCargoVendor {
            src = ./.;
            hash = "sha256-MKGGtq68rGeH83X0o6MRJ2EmH7yqWBb1vDcrkOGqAgc=";
          };

          # Combined LLVM 22 for bpf-linker
          llvm22 = pkgs.symlinkJoin {
            name = "llvm-22-combined";
            paths = [ pkgs.llvmPackages_22.llvm.dev pkgs.llvmPackages_22.llvm.lib ];
          };

          # bpf-linker v0.10.1 with LLVM 22
          bpfLinker = pkgs.rustPlatform.buildRustPackage rec {
            pname = "bpf-linker";
            version = "0.10.1";
            src = pkgs.fetchFromGitHub {
              owner = "aya-rs";
              repo = "bpf-linker";
              tag = "v${version}";
              hash = "sha256-WFMQlaM18v5FsrsjmAl1nPGNMnBW3pjXmkfOfv3Izq0=";
            };
            cargoHash = "sha256-m/mlN1EL5jYxprNXvMbuVzBsewdIOFX0ebNQWfByEHQ=";
            buildNoDefaultFeatures = true;
            buildFeatures = [ "llvm-${pkgs.lib.versions.major pkgs.llvmPackages_22.llvm.version}" ];
            LLVM_PREFIX = "${llvm22}";
            nativeBuildInputs = [ llvm22 ];
            buildInputs = [ pkgs.zlib pkgs.libxml2 ];
            doCheck = false;
          };

          # Custom FOD: vendors eBPF deps + std library deps (for -Z build-std=core)
          ebpfVendor = pkgs.stdenvNoCC.mkDerivation {
            name = "shapebpf-ebpf-vendor";
            src = ./.;
            postUnpack = "sourceRoot=$sourceRoot/shapebpf-ebpf";
            nativeBuildInputs = [ rustNightly pkgs.cacert ];
            dontBuild = true;
            dontFixup = true;
            installPhase = ''
              mkdir -p $out/.cargo
              sysroot=$(rustc --print sysroot)
              HOME=$(mktemp -d) cargo vendor \
                --locked \
                --sync "$sysroot/lib/rustlib/src/rust/library/Cargo.toml" \
                $out 2>/dev/null > vendor-config.toml
              sed "s|$out|@vendor@|g" vendor-config.toml > $out/.cargo/config.toml
            '';
            outputHashMode = "recursive";
            outputHashAlgo = "sha256";
            outputHash = "sha256-8UTxMLocj69kTJdv+mN7YAF1/MXrdgp4cI7EpqRsFjk=";
          };

          mkShapebpf = { pname, rustToolchain, cargoTarget ? null, extraNativeBuildInputs ? [], env ? {} }:
            let
              targetFlag = if cargoTarget != null then "--target ${cargoTarget}" else "";
              outputDir = if cargoTarget != null then "target/${cargoTarget}/release" else "target/release";
            in pkgs.stdenv.mkDerivation ({
              inherit pname;
              version = "0.1.0";
              src = ./.;

              nativeBuildInputs = [
                rustToolchain
                bpfLinker
                pkgs.llvmPackages_22.clang
                pkgs.llvmPackages_22.llvm
                pkgs.pkg-config
                pkgs.bpftools
              ] ++ extraNativeBuildInputs;

              buildInputs = [ pkgs.elfutils pkgs.zlib pkgs.linuxPackages_latest.kernel.dev ];

              configurePhase = ''
                runHook preConfigure

                export HOME=$(mktemp -d)

                # Vendor workspace deps
                mkdir -p .cargo
                substitute ${workspaceVendor}/.cargo/config.toml .cargo/config.toml \
                  --subst-var-by vendor ${workspaceVendor}
                echo '[alias]' >> .cargo/config.toml
                echo 'xtask = "run --package xtask --"' >> .cargo/config.toml

                # Vendor eBPF deps + linker config
                mkdir -p shapebpf-ebpf/.cargo
                substitute ${ebpfVendor}/.cargo/config.toml shapebpf-ebpf/.cargo/config.toml \
                  --subst-var-by vendor ${ebpfVendor}
                echo '[target.bpfel-unknown-none]' >> shapebpf-ebpf/.cargo/config.toml
                echo 'linker = "bpf-linker"' >> shapebpf-ebpf/.cargo/config.toml
                echo 'rustflags = ["-Clink-arg=--btf"]' >> shapebpf-ebpf/.cargo/config.toml

                runHook postConfigure
              '';

              buildPhase = let
                archFeature = {
                  "x86_64-linux" = "arch-x86_64";
                  "aarch64-linux" = "arch-aarch64";
                }.${system};
              in ''
                runHook preBuild

                # Phase 1a: Build Rust eBPF (tracepoints)
                pushd shapebpf-ebpf
                cargo build --target bpfel-unknown-none -Z build-std=core --release --features ${archFeature}
                popd

                # Phase 1b: Build C eBPF (qdisc struct_ops)
                mkdir -p shapebpf-ebpf/target/bpf

                # Generate vmlinux.h from the kernel package's BTF
                # (can't use /sys/kernel/btf/vmlinux in nix sandbox)
                vmlinux="${pkgs.linuxPackages_latest.kernel.dev}/vmlinux"
                if [ -f "$vmlinux" ]; then
                  # Strip __weak __ksym kfunc declarations from vmlinux.h.
                  # These produce FUNC entries in .ksyms BTF DATASEC that libbpf
                  # transforms into dummy_ksym VARs, which the kernel rejects.
                  # We provide our own kfunc declarations in bpf_kfuncs.h instead.
                  bpftool btf dump file "$vmlinux" format c \
                    | sed '/^extern.*__ksym;$/d' \
                    > shapebpf-ebpf/src/bpf/vmlinux.h
                  # Use stable LLVM 19 for C BPF compilation
                  ${pkgs.llvmPackages_19.clang-unwrapped}/bin/clang -target bpf -mcpu=v4 -g -O2 -Wall \
                    -D__TARGET_ARCH_${if system == "x86_64-linux" then "x86" else "arm64"} \
                    -I shapebpf-ebpf/src/bpf \
                    -I ${pkgs.libbpf}/include \
                    -c shapebpf-ebpf/src/bpf/qdisc.bpf.c \
                    -o shapebpf-ebpf/target/bpf/qdisc.bpf.o
                else
                  echo "WARNING: kernel vmlinux not found, creating minimal BPF stub"
                  echo "int _placeholder = 0;" | ${pkgs.llvmPackages_19.clang-unwrapped}/bin/clang -target bpf -g -O2 -c -x c - -o shapebpf-ebpf/target/bpf/qdisc.bpf.o
                fi

                # Phase 2: Build userspace (embeds eBPF objects)
                cargo build --release --bin shapebpf-daemon --bin shapebpf-tui ${targetFlag}

                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p $out/bin
                cp ${outputDir}/shapebpf-daemon $out/bin/
                cp ${outputDir}/shapebpf-tui $out/bin/
                # Include the C qdisc source and compiled BPF object for debugging
                mkdir -p $out/share/shapebpf
                cp shapebpf-ebpf/src/bpf/qdisc.bpf.c $out/share/shapebpf/
                cp shapebpf-ebpf/target/bpf/qdisc.bpf.o $out/share/shapebpf/
                runHook postInstall
              '';
            } // env);

        in {
          default = mkShapebpf {
            pname = "shapebpf";
            rustToolchain = rustNightly;
            env = {
              GIT_HASH = self.shortRev or self.dirtyShortRev or "dev";
            };
          };
        }
      );

      devShells = forAllSystems ({ pkgs, system }: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            (rust-bin.nightly.latest.default.override {
              extensions = [ "rust-src" ];
            })
            fenix.packages.${system}.rust-analyzer
            llvmPackages_22.clang
            llvmPackages_22.llvm
            bpftools
            pkg-config
            elfutils
            zlib
            libbpf
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages_22.libclang.lib}/lib";
          LIBBPF_INCLUDE = "${pkgs.libbpf}/include";

          shellHook = ''
            export PATH="$HOME/.cargo/bin:$PATH"
          '';
        };
      });

      nixosModules.default = import ./nix/module.nix self;

      # Interactive dev VM: nix run .#dev-vm then ssh -p 2222 root@localhost (password: root)
      apps = forAllSystems ({ pkgs, system }: {
        dev-vm = {
          type = "app";
          program = "${import ./nix/dev-vm.nix { inherit self nixpkgs system; }}/bin/run-nixos-vm";
        };
      });

      # VM tests
      checks = forAllSystems ({ pkgs, system }: {
        bandwidth-limit = import ./nix/tests/bandwidth-limit.nix {
          inherit pkgs;
          shapebpfModule = self.nixosModules.default;
        };
      });
    };
}
