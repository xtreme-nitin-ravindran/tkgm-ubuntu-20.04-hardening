# encoding: UTF-8

control 'V-238293' do
  title "The Ubuntu operating system must generate audit records for
successful/unsuccessful uses of the crontab command."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that an audit event is generated for any successful/unsuccessful use
of the \"crontab\" command.

    Check the currently configured audit rules with the following command:

    $ sudo auditctl -l | grep -w crontab

    -a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1
-k privileged-crontab

    If the command does not return a line that matches the example or the line
is commented out, this is a finding.

    Note: The \"-k\" allows for specifying an arbitrary identifier, and the
string after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful uses of the \"crontab\" command.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged-crontab

    To reload the rules file, issue the following command:

    $ sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag gid: 'V-238293'
  tag rid: 'SV-238293r654054_rule'
  tag stig_id: 'UBTU-20-010177'
  tag fix_id: 'F-41462r654053_fix'
  tag cci: ['CCI-000172']
  tag legacy: []
  tag nist: ['AU-12 c']

  @audit_file = '/usr/bin/crontab'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  else
    describe ('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
