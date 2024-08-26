# Ensure Access to the su command is restricted
control "cisecurity.benchmarks_rule_5.6_Ensure_access_to_the_su_command_is_restricted" do
  title "Ensure access to the su command is restricted"
  
  desc "The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access. 
  Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su, the su command will only allow users in the wheel group to execute su."
  
  impact 1.0
  tag "cis-ubuntu-24.04": "5.6"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]

  describe file("/etc/pam.d/su") do
    its("content") { should match(/^\s*auth\s+required\s+pam_wheel\.so\s+(\S+\s+)*use_uid\s*(\S+\s+)*$/) }
  end
end
