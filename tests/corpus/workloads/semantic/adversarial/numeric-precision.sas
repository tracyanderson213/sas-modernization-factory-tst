/* Primary behavior: binary floating point equality, rounding, and explicit tolerance. */
data work.numeric_precision;
    tenth_sum = 0.1 + 0.2;
    literal = 0.3;
    equal_raw = (tenth_sum = literal);
    rounded = round(tenth_sum, 0.01);
    tolerant_measure = 1 / 3;
run;
