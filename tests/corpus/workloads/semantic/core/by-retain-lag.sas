/* SMF-authored semantic fixture: FIRST./LAST., RETAIN, and LAG behavior. */
data work.visits;
    input member_id $ visit_date :date9. systolic;
    format visit_date date9.;
datalines;
M001 01JAN2026 130
M001 15JAN2026 142
M001 01FEB2026 138
M002 05JAN2026 118
M002 20JAN2026 121
;
run;

proc sort data=work.visits; by member_id visit_date; run;

data work.visit_summary;
    set work.visits;
    by member_id visit_date;
    retain first_systolic;
    previous_systolic = lag(systolic);
    if systolic >= 120 then conditional_previous = lag(systolic);
    if first.member_id then do;
        first_systolic = systolic;
        previous_systolic = .;
    end;
    change_from_previous = systolic - previous_systolic;
    if last.member_id then output;
run;
