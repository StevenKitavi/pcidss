control "cisecurity.benchmarks_rule_3.6.2_Ensure_default_deny_firewall_policy" do
  title "Ensure default deny firewall policy"
  
  desc "A default deny all policy on connections ensures that any unconfigured network usage will be rejected. 
  Rationale: With a default accept policy, the firewall will accept any packet that is not configured to be denied. 
  It is easier to whitelist acceptable usage than to blacklist unacceptable usage."
  
  impact 1.0
  tag "cis-ubuntu-24.04": "3.6.2"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]

  %w[INPUT OUTPUT FORWARD].each do |chain|
    describe.one do
      describe iptables do
        it { should have_rule("-P #{chain} DROP") }
      end
      describe iptables do
        it { should have_rule("-P #{chain} REJECT") }
      end
    end
  end
end
