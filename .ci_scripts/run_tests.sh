EXITCODE=0
VALGRIND_SUPP=".ci_scripts/valgrind.supp"

for file in bin/test/*
do
    if [[ $# -eq 1 && $1 == valgrind ]]
    then
        valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --suppressions="$VALGRIND_SUPP" --error-exitcode=1 "$file"
    else
        "$file"
    fi

    # If the exit code is not 0, set EXITCODE to 1
    if [[ $? -ne 0 ]]
    then
        EXITCODE=1
    fi
done

exit $EXITCODE
