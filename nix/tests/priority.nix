{ pkgs, shapebpfModule }:

pkgs.testers.runNixOSTest {
  name = "shapebpf-priority";

  nodes = {
    server = { config, pkgs, ... }: {
      boot.kernelPackages = pkgs.linuxPackages_latest;
      networking.firewall.allowedTCPPorts = [ 5201 5202 ];
      environment.systemPackages = [ pkgs.iperf3 ];
    };

    client = { config, pkgs, ... }: {
      imports = [ shapebpfModule ];
      boot.kernelPackages = pkgs.linuxPackages_latest;

      services.shapebpf = {
        enable = true;
        interface = "eth1";
        defaultRule = {
          egressRateBps = 2097152; # 2 MB/s total
          priority = 5;
        };
        rules = [
          {
            name = "high-priority";
            processName = "iperf3-hi";
            priority = 1;
          }
          {
            name = "low-priority";
            processName = "iperf3-lo";
            priority = 10;
          }
        ];
      };

      environment.systemPackages = [ pkgs.iperf3 ];
    };
  };

  testScript = ''
    start_all()

    server.wait_for_unit("network.target")
    client.wait_for_unit("network.target")

    # Start two iperf3 servers on different ports
    server.succeed("iperf3 -s -p 5201 -D")
    server.succeed("iperf3 -s -p 5202 -D")

    client.wait_for_unit("shapebpf.service")
    client.sleep(3)

    # Run both iperf3 clients simultaneously
    # High priority should get more bandwidth
    client.succeed("iperf3 -c server -p 5201 -t 10 -J > /tmp/hi.json &")
    client.succeed("iperf3 -c server -p 5202 -t 10 -J > /tmp/lo.json &")

    # Wait for both to complete
    client.sleep(15)

    import json

    hi = json.loads(client.succeed("cat /tmp/hi.json"))
    lo = json.loads(client.succeed("cat /tmp/lo.json"))

    hi_bps = hi["end"]["sum_sent"]["bits_per_second"]
    lo_bps = lo["end"]["sum_sent"]["bits_per_second"]

    print(f"High priority: {hi_bps/1e6:.2f} Mbps")
    print(f"Low priority: {lo_bps/1e6:.2f} Mbps")

    # High priority should get significantly more bandwidth
    assert hi_bps > lo_bps, f"High priority ({hi_bps/1e6:.2f}) should exceed low priority ({lo_bps/1e6:.2f})"
  '';
}
