control "cisecurity.benchmarks_rule_5.3.1_Ensure_password_creation_requirements" do
  title "Ensure password creation requirements are configured"
  desc "The pam_pwquality.so module checks the strength of passwords.
  The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies. 
  Rationale: Strong passwords protect systems from being hacked through brute force methods."
  impact 1.0
  tag "cis-ubuntu-20.04": "2.0.1"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*try_first_pass/) }
    its('content') { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*retry=[3210]/) }
  end
  describe file('/etc/pam.d/password-auth') do
    its('content') { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*try_first_pass/) }
    its('content') { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*retry=[3210]/) }
  end
  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minlen') { should match(/1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+/) }
    its('dcredit') { should match(/-[1-9][0-9]{0,}/) }
    its('ucredit') { should match(/-[1-9][0-9]{0,}/) }
    its('ocredit') { should match(/-[1-9][0-9]{0,}/) }
    its('lcredit') { should match(/-[1-9][0-9]{0,}/) }
  end
end
