#Ensure SSH MaxAuthTries is set to 4 or less 
control "cisecurity.benchmarks_rule_5.2.5_Ensure_SSH_MaxAuthTries_set_ to_4_or_less" do
  title "Ensure SSH MaxAuthTries is set to 4 or less"
  desc "The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file. Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server."
  impact 1.0
  tag "cis-rhel7-2.1.1": "5.2.5"
  tag "level": "1"
  tag "type": ["Server", "Workstation"] 
  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 } 
  end
end