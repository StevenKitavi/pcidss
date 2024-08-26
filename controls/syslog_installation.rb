#Ensure rsyslog or syslog-ng is installed 
control "cisecurity.benchmarks_rule_4.2.3_Ensure_rsyslog_or_syslog-ng_ is_installed" do
  title "Ensure rsyslog or syslog-ng is installed"
  desc "The rsyslog and syslog-ng software are recommended replacements to the original syslogd daemon which provide improvements over syslogd. The security enhancements of rsyslog and syslog-ng such justify installing and configuring the package."
  impact 1.0
  tag "cis-ubuntu-24.04": "4.2.3"
  tag "level": "1"
  tag "type": ["Server", "Workstation"] 
  describe.one do
    describe package("rsyslog") do 
        it { should be_installed }
    end
    describe package("syslog-ng") do 
        it { should be_installed }
    end 
  end
end