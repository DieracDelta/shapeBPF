flake:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.shapebpf;
  settingsFormat = pkgs.formats.toml { };

  configFile = settingsFormat.generate "config.toml" {
    general = {
      interface = cfg.interface;
      stats_interval_ms = cfg.statsIntervalMs;
    };
    default_rule = {
      egress_rate_bps = cfg.defaultRule.egressRateBps;
      ingress_rate_bps = cfg.defaultRule.ingressRateBps;
      priority = cfg.defaultRule.priority;
    };
    rules = builtins.map (r: lib.filterAttrs (_: v: v != null) {
      name = r.name;
      user = r.user;
      container_name = r.containerName;
      service_unit = r.serviceUnit;
      cgroup_path = r.cgroupPath;
      process_name = r.processName;
      egress_rate_bps = r.egressRateBps;
      ingress_rate_bps = r.ingressRateBps;
      priority = r.priority;
    }) cfg.rules;
  };
in {
  options.services.shapebpf = {
    enable = lib.mkEnableOption "shapeBPF per-process bandwidth shaping daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.system}.default;
      description = "The shapebpf package to use.";
    };

    interface = lib.mkOption {
      type = lib.types.str;
      default = "eth0";
      description = "Network interface to attach the qdisc to.";
    };

    statsIntervalMs = lib.mkOption {
      type = lib.types.int;
      default = 1000;
      description = "How often to read traffic stats from BPF maps (milliseconds).";
    };

    defaultRule = {
      egressRateBps = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = "Default egress rate limit in bytes/sec (0 = unlimited).";
      };
      ingressRateBps = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = "Default ingress rate limit in bytes/sec (0 = unlimited).";
      };
      priority = lib.mkOption {
        type = lib.types.ints.between 1 10;
        default = 8;
        description = "Default priority (1=highest, 10=lowest).";
      };
    };

    rules = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          name = lib.mkOption { type = lib.types.str; };
          user = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
          containerName = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
          serviceUnit = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
          cgroupPath = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
          processName = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
          egressRateBps = lib.mkOption { type = lib.types.nullOr lib.types.int; default = null; };
          ingressRateBps = lib.mkOption { type = lib.types.nullOr lib.types.int; default = null; };
          priority = lib.mkOption {
            type = lib.types.ints.between 1 10;
            default = 5;
          };
        };
      });
      default = [];
      description = "Traffic shaping rules. First match wins.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "shapebpf";
      description = "Group allowed to connect to the TUI socket.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = {};

    systemd.services.shapebpf = {
      description = "shapeBPF bandwidth shaping daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        Environment = "RUST_LOG=debug";
        ExecStart = "${cfg.package}/bin/shapebpf-daemon run --config ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;

        # Required capabilities for eBPF and network qdisc management
        AmbientCapabilities = [
          "CAP_NET_ADMIN"
          "CAP_BPF"
          "CAP_SYS_ADMIN"
          "CAP_PERFMON"
        ];
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_BPF"
          "CAP_SYS_ADMIN"
          "CAP_PERFMON"
        ];

        # Socket directory
        RuntimeDirectory = "shapebpf";
        RuntimeDirectoryMode = "0750";

        # Persistent state (rules.json)
        StateDirectory = "shapebpf";
        StateDirectoryMode = "0750";

        # Security hardening
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectControlGroups = false; # needed for PID isolation (child cgroup creation)
        NoNewPrivileges = false; # needed for BPF
        Delegate = true;
        ReadWritePaths = [ "/run/shapebpf" "/sys/fs/bpf" "/var/lib/shapebpf" ];
      };
    };

    # Allow TUI users in the shapebpf group to access the socket
    systemd.tmpfiles.rules = [
      "d /run/shapebpf 0750 root ${cfg.group} -"
    ];

    # Add the TUI binary to the system path
    environment.systemPackages = [ cfg.package ];
  };
}
