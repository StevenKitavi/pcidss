#Ensure Suspicious packets are logged
control "cisecurity.benchmarks_rule_3.2.4_Ensure_suspicious_packets_are_ logged" do
  title "Ensure suspicious packets are logged"
  desc "When enabled, this feature logs packets with un-routable source addresses to the kernel log. Rationale: Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system."
  impact 1.0
  tag "cis-ubuntu-24.04": "3.2.4"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do 
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.log_martians') do 
    its('value') { should eq 1 }
  end 
end