/* This whole block must NOT create lineage:
   data fake.comment_output;
     set fake.comment_input;
   run;
*/

* set fake.statement_comment_input; ;

LiBnAmE Src ODBC
    dsn="claims warehouse"
    schema=prod
    user=svc_reader
    password="SUPER_SECRET_DO_NOT_LEAK";

libname out "/tmp/output path with spaces";

%let suffix=202608;
%let source_table=claims_&suffix.;

%include "includes/real_include.sas";

DATA out.literal_output;
    SET src.literal_input;
run;

/* Dynamic source must remain unresolved, not be guessed as src.source_table. */
data out.dynamic_output;
    set src.&source_table.;
run;

proc sql;
    create table out.sql_output as
    select a.member_id, b.flag
    from src.member a
    left join src.flags b
      on a.member_id=b.member_id;
quit;

/* SAS keywords inside a quoted string must not manufacture dependencies. */
data out.string_case;
    length note $200;
    note='set fake.string_input; create table fake.string_output as select * from fake.x;';
run;

/* Work dataset should be characterized as an intermediate. */
data work.stage;
    merge src.member src.claims;
    by member_id;
run;
