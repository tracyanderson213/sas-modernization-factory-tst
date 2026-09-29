/* Primary behavior: deterministic character/numeric coercion. */
data work.coercion;
    length raw $8 roundtrip $8;
    input raw $char8.;
    numeric_value = input(strip(raw), ?? best32.);
    roundtrip = put(numeric_value, z4.);
datalines;
42
0042
 7
bad
;
run;
