#Ensure SSH PermitEmptyPasswords is disabled 
control "cisecurity.benchmarks_rule_5.2.9_Ensure_SSH_ PermitEmptyPasswords_is_disabled" do
  title "Ensure SSH PermitEmptyPasswords is disabled"
  desc "The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings. Rationale: Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system"
  impact 1.0
  tag "cis-rhel7-2.1.1": "5.2.9"
  tag "level": "1"
  tag "type": ["Server", "Workstation"] 
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' } 
  end
end