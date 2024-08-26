#Ensure SSH LogLevel is set to INFO
control "cisecurity.benchmarks_rule_5.2.3_Ensure_SSH_LogLevel_is_set_to_ INFO" do
  title "Ensure SSH LogLevel is set to INFO"
  desc "The INFO parameter specifies that login and logout activity will be logged. Rationale: SSH provides several logging levels with varying amounts of verbosity. INFO level is the basic level that only records login and logout activity of SSH users."
  impact 1.0
  tag "cis-rhel7-2.1.1": "5.2.3"
  tag "level": "1"
  tag "type": ["Server", "Workstation"] 
  describe sshd_config do
   its('LogLevel') { should eq 'INFO' } 
  end
end