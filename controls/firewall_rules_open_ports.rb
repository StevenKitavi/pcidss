control "cisecurity.benchmarks_rule_3.6.5_Ensure_firewall_rules_for_open_ports" do
  title "Ensure firewall rules exist for all open ports"

  desc "Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic. 
  Rationale: Without a firewall rule configured for open ports, the default firewall policy will drop all packets to these ports."

  impact 1.0
  tag "cis-ubuntu-24.04": "3.6.5"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]

  port.where { protocol =~ /.*/ && port >= 0 && address =~ /^(?!127\.0\.0\.1|::1|::).*$/ }.entries.each do |entry|
    rule_inbound = "-A INPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --dport #{entry[:port]} -m state --state NEW,ESTABLISHED -j ACCEPT"
    rule_outbound = "-A OUTPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --sport #{entry[:port]} -m state --state ESTABLISHED -j ACCEPT"

    describe iptables do
      it { should have_rule(rule_inbound) }
      it { should have_rule(rule_outbound) }
    end
  end
end
