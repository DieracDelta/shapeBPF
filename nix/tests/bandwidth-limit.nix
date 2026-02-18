{ pkgs, shapebpfModule }:

pkgs.testers.runNixOSTest {
  name = "shapebpf-bandwidth-limit";

  nodes = {
    server = { config, pkgs, ... }: {
      boot.kernelPackages = pkgs.linuxPackages_latest;
      networking.firewall.allowedTCPPorts = [ 5201 ];
      environment.systemPackages = [ pkgs.iperf3 ];
    };

    client = { config, pkgs, ... }: {
      imports = [ shapebpfModule ];
      boot.kernelPackages = pkgs.linuxPackages_latest;

      services.shapebpf = {
        enable = true;
        interface = "eth1";
        defaultRule = {
          egressRateBps = 1048576; # 1 MB/s
          ingressRateBps = 5242880; # 5 MB/s
          priority = 8;
        };
      };

      environment.systemPackages = [ pkgs.iperf3 ];
    };
  };

  testScript = ''
    start_all()

    server.wait_for_unit("network.target")
    client.wait_for_unit("network.target")

    # Start iperf3 server
    server.succeed("iperf3 -s -D")

    # Wait for shapebpf daemon to start and qdisc to attach
    client.wait_for_unit("shapebpf.service")
    client.sleep(3)

    # Verify daemon is running
    client.succeed("systemctl is-active shapebpf.service")

    # Run iperf3 bandwidth test
    result = client.succeed("iperf3 -c server -t 5 -J")

    import json
    data = json.loads(result)
    bandwidth_bps = data["end"]["sum_sent"]["bits_per_second"]
    bandwidth_mbps = bandwidth_bps / 1_000_000
    print(f"Measured bandwidth: {bandwidth_mbps:.2f} Mbps")

    # Check kernel version to determine if rate limiting should be active
    kernel_ver = client.succeed("uname -r").strip()
    print(f"Kernel version: {kernel_ver}")

    parts = kernel_ver.split(".")
    major, minor = int(parts[0]), int(parts[1])
    if major > 6 or (major == 6 and minor >= 16):
        # Rate limiting should be active (1 MB/s = 8 Mbps, allow some overhead)
        assert bandwidth_mbps < 12, f"Bandwidth {bandwidth_mbps:.2f} Mbps exceeds limit (expected < 12 Mbps)"
        print("PASS: Rate limiting is active")
    else:
        print(f"SKIP: Kernel {kernel_ver} < 6.16, sch_bpf not available. Monitor-only mode.")
        assert bandwidth_mbps > 0, "No bandwidth measured"
        print("PASS: Monitor-only mode working correctly")

    # Verify daemon is still healthy after traffic
    client.succeed("systemctl is-active shapebpf.service")
  '';
}
