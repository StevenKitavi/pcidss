control "cisecurity.benchmarks_rule_5.4.2_Ensure_system_accounts_are_ non-login" do
title "Ensure system accounts are non-login"
desc "There are a number of accounts provided with Red Hat 7 that are used to manage applications and are not intended to provide an interactive shell. Rationale: Prevent them from being used to provide an interactive shell."
impact 1.0
tag "cis-rhel7-2.1.1": "5.4.2"
tag "level": "1"
tag "type": ["Server", "Workstation"]
describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ } do 
  its("entries") { should_not be_empty }
end
describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ && uid.to_i < 1000 && shell != "/sbin/nologin" } do
its("entries") { should be_empty } 
  end
end