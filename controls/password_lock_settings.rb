control "cisecurity.benchmarks_rule_5.4.1.4_Ensure_inactive_pass_lock_ is_30_days_or_less" do
   title "Ensure inactive password lock is 30 days or less"
   desc "User accounts that have been inactive for over a given period of time can be automatically disabled. Rationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies." 
   impact 1.0
   describe file("/etc/default/useradd") do 
    its("content") { should match(/^\s*INACTIVE\s*=\s*(30|[1-2][0-9]|[1-9])\s*(\s+#.*)?$/) } 
   end
   describe bash( "#!/usr/bin/env sh\n\n#\n# CIS-CAT Script Check Engine\n# \n# Name Date Description\n# --------------
---------------------------------------------------------------------------\n# B. Munyan
7/20/16 Ensure no users have a password inactivity period > 30\n#
\n\noutput=$(\n/usr/bin/getent shadow | awk -F : 'match($2, /^[^!*]/) && ($7 == \"\" || $7 > 30) { if ($7 == \"\") { print \"User \" $1 \" password inactivity period is not defined\" } else { print \"User \" $1
\" Password Inactivity Period > 30 (\" $7 \") \" } }'\n)\n\n# we captured output of the subshell, let's interpret it\nif [ \"$output\" == \"\" ]
; then\n exit $ XCCDF_RESULT_PASS\nelse\n # print the reason why we are failing\n echo \"$output\"\n exit $XCCDF_RESULT_FAIL\ nfi\n") do
 its("exit_status") { should eq 0 } 
 end
end