# Ensure permissions on all log files are configured
control "cisecurity.benchmarks_rule_4.2.4_Ensure_perms_on_all_logfiles_configured" do
  title "Ensure permissions on all log files are configured"

  desc "Log files stored in /var/log/ contain logged information from many services on the system, or on log hosts others as well. 
  Rationale: It is important to ensure that log files have the correct permissions."

  impact 1.0
  tag "cis-ubuntu-24.04": "4.2.4"
  tag "level": "1"
  tag "type": ["Server", "Workstation"]

  command('find /var/log -type f').stdout.split("\n").each do |log_file|
    describe file(log_file) do
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('group') }
      it { should_not be_readable.by('other') }
      it { should_not be_writable.by('other') }
      it { should_not be_executable.by('other') }
    end
  end
end
