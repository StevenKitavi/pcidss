control "xccdf_org.cisecurity.benchmarks_rule_3.6.1_Ensure_iptables_is_ Installed" do
  title "Ensure iptables is installed"
  desc "iptables allows configuration of the IPv4 tables in the linux kernel and the rules stored within them. Rationale: iptables is required for firewall management and configuration."
  impact 1.0
  tag "cis-rhel7-2.1.1": "3.6.1"
  tag "level": "1"
  tag "type": ["Server", "Workstation"] 
  describe package('iptables') do
    it { should be_installed } 
   end
end