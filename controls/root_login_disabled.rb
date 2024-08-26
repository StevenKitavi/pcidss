# Ensure SSH root login is disabled
control "cisecurity.benchmarks_rule_5.2.8_Ensure_SSH_root_login_is_disabled" do
  title "Ensure SSH root login is disabled"

  desc "The PermitRootLogin parameter specifies if the root user can login using ssh(1). The default is no. 
  Rationale: Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalate to root via sudo."

  impact 1.0
  tag "cis-ubuntu-24.04": "5.2.8"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]

  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
end
