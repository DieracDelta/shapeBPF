{ self, nixpkgs, system }:

let
  pkgs = import nixpkgs { inherit system; };

  nixos = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      ({ config, pkgs, lib, modulesPath, ... }: {
        imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

        boot.kernelPackages = pkgs.linuxPackages_latest;

        services.shapebpf = {
          enable = true;
          interface = "eth0";
          defaultRule = {
            egressRateBps = 1048576;  # 1 MB/s
            ingressRateBps = 5242880; # 5 MB/s
            priority = 8;
          };
        };

        services.openssh = {
          enable = true;
          settings = {
            PermitRootLogin = "yes";
            PasswordAuthentication = true;
          };
        };

        users.users.root.password = "root";
        services.getty.autologinUser = "root";

        networking.firewall.enable = false;

        environment.systemPackages = with pkgs; [
          iperf3
          bpftools
          iproute2
        ];

        virtualisation = {
          memorySize = 2048;
          cores = 2;
          forwardPorts = [
            { from = "host"; host.port = 2222; guest.port = 22; }
          ];
          graphics = false;
        };
      })
    ];
  };
in
  nixos.config.system.build.vm
