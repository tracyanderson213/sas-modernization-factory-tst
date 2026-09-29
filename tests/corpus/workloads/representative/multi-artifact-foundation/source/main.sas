%include "includes/configure.sas";
%include "macros/member_rules.sas";

%member_rules(source=work.members, target=work.eligible_members);
