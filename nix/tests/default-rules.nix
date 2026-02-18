{ pkgs, shapebpfModule }:

pkgs.testers.runNixOSTest {
  name = "shapebpf-default-rules";

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
        # Strict default: 512 KB/s for unclassified processes
        defaultRule = {
          egressRateBps = 524288;
          ingressRateBps = 524288;
          priority = 10;
        };
        # But exempt the test user
        rules = [
          {
            name = "exempt-root";
            user = "root";
            priority = 1;
            # No rate limit = unlimited
          }
        ];
      };

      environment.systemPackages = [ pkgs.iperf3 ];

      # Create a test user
      users.users.testuser = {
        isNormalUser = true;
        uid = 1001;
      };
    };
  };

  testScript = ''
    start_all()

    server.wait_for_unit("network.target")
    client.wait_for_unit("network.target")

    server.succeed("iperf3 -s -D")
    client.wait_for_unit("shapebpf.service")
    client.sleep(3)

    # Test as testuser (should be rate-limited by default rule)
    result = client.succeed("su -c 'iperf3 -c server -t 5 -J' testuser")

    import json
    data = json.loads(result)
    bandwidth_bps = data["end"]["sum_sent"]["bits_per_second"]
    bandwidth_kbps = bandwidth_bps / 1_000

    print(f"Unclassified user bandwidth: {bandwidth_kbps:.0f} Kbps")

    # 512 KB/s = ~4 Mbps, allow generous tolerance
    assert bandwidth_bps < 8_000_000, f"Unclassified bandwidth {bandwidth_bps/1e6:.2f} Mbps exceeds expected limit"

    client.succeed("systemctl is-active shapebpf.service")
  '';
}
