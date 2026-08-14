#!/bin/sh

# ============================================================
# Stormshield SNS
#
# IP -> HOST -> GROUP -> FILTER/NAT RULES
#
# Bemenet:
#   /tmp/ips.txt
#
# Target:
#   /tmp/firewall-config
#
# Kimenet:
#   /tmp/firewall-rules.csv
#
# Futtatás:
#   /bin/sh /tmp/fw-object-rules.sh
# ============================================================


# ============================================================
# CONFIG
# ============================================================

IP_FILE="/tmp/ips.txt"
TARGET_FILE="/tmp/firewall-config"
OUTPUT_FILE="/tmp/firewall-rules.csv"

WORK="/tmp/fwquery.$$"

CMD_HOST="$WORK.host.cmd"
OUT_HOST="$WORK.host.out"

CMD_CHECK="$WORK.check.cmd"
OUT_CHECK="$WORK.check.out"

CMD_RULE="$WORK.rule.cmd"
OUT_RULE="$WORK.rule.out"

HOST_MAP="$WORK.hostmap"
RULE_MAP="$WORK.rulemap"


# ============================================================
# CLEANUP
# ============================================================

umask 077

cleanup()
{
    rm -f "$CMD_HOST"
    rm -f "$OUT_HOST"
    rm -f "$CMD_CHECK"
    rm -f "$OUT_CHECK"
    rm -f "$CMD_RULE"
    rm -f "$OUT_RULE"
    rm -f "$HOST_MAP"
    rm -f "$RULE_MAP"
}

trap cleanup 0 1 2 3 15


# ============================================================
# CHECK INPUT
# ============================================================

if [ ! -f "$IP_FILE" ]; then
    echo "ERROR: IP lista nem található:"
    echo "$IP_FILE"
    exit 1
fi

if [ ! -f "$TARGET_FILE" ]; then
    echo "ERROR: target file nem található:"
    echo "$TARGET_FILE"
    exit 1
fi


# ============================================================
# OUTPUT
# ============================================================

rm -f "$OUTPUT_FILE"

echo 'LINE;RULEID;POSITION;RULE' > "$OUTPUT_FILE"


# ============================================================
# 1. IP -> HOST
# ============================================================

echo
echo "============================================================"
echo "1. IP -> HOST"
echo "============================================================"

rm -f "$CMD_HOST"
rm -f "$OUT_HOST"
rm -f "$HOST_MAP"


# ------------------------------------------------------------
# HOST lookup parancsok
# ------------------------------------------------------------

while IFS= read ip
do

    case "$ip" in
        "")
            continue
            ;;
        \#*)
            continue
            ;;
    esac

    ip=`echo "$ip" | sed 's/^[  ]*//;s/[        ]*$//'`

    if [ -z "$ip" ]; then
        continue
    fi

    echo "CONFIG OBJECT LIST type=host start=0 search=$ip searchfield=ip" \
        >> "$CMD_HOST"

done < "$IP_FILE"


if [ ! -s "$CMD_HOST" ]; then
    echo "ERROR: nincs feldolgozható IP."
    exit 1
fi


# ------------------------------------------------------------
# HOST lookup
# ------------------------------------------------------------

nsrpc \
    -c "$CMD_HOST" \
    -t "$TARGET_FILE" \
    -l "$OUT_HOST" \
    >/dev/null 2>&1


if [ ! -f "$OUT_HOST" ]; then
    echo "ERROR: HOST lookup output nem jött létre."
    exit 1
fi


# ------------------------------------------------------------
# HOST eredmény feldolgozása
# ------------------------------------------------------------

while IFS= read ip
do

    case "$ip" in
        "")
            continue
            ;;
        \#*)
            continue
            ;;
    esac

    ip=`echo "$ip" | sed 's/^[  ]*//;s/[        ]*$//'`

    awk -v wanted="$ip" '
    /type="host"/ {

        obj_ip=""
        obj_name=""

        for (i=1; i<=NF; i++) {

            x=$i

            if (index(x, "ip=\"") == 1) {
                x=substr(x, 5)
                gsub(/"/, "", x)
                obj_ip=x
            }

            if (index(x, "name=\"") == 1) {
                x=substr(x, 7)
                gsub(/"/, "", x)
                obj_name=x
            }
        }

        if (obj_ip == wanted && obj_name != "") {
            print wanted "\t" obj_name
        }
    }
    ' "$OUT_HOST"

done < "$IP_FILE" >> "$HOST_MAP"


if [ ! -s "$HOST_MAP" ]; then
    echo
    echo "Nem találtam host objektumot."
    exit 0
fi


echo
echo "Talált objektumok:"
echo "------------------"

awk -F '        ' '
{
    print $1 " -> " $2
}
' "$HOST_MAP"


# ============================================================
# 2. HOST CHECK
# ============================================================

echo
echo "============================================================"
echo "2. HOST CHECK"
echo "============================================================"

rm -f "$CMD_CHECK"
rm -f "$OUT_CHECK"
rm -f "$RULE_MAP"


# ------------------------------------------------------------
# HOST CHECK parancsok
#
# Egy hostot csak egyszer kérdezünk le.
# ------------------------------------------------------------

awk -F '        ' '
{
    host=$2

    if (!(host in seen)) {
        print "CONFIG OBJECT HOST CHECK name=" host
        seen[host]=1
    }
}
' "$HOST_MAP" > "$CMD_CHECK"


# ------------------------------------------------------------
# HOST CHECK
# ------------------------------------------------------------

nsrpc \
    -c "$CMD_CHECK" \
    -t "$TARGET_FILE" \
    -l "$OUT_CHECK" \
    >/dev/null 2>&1


if [ ! -f "$OUT_CHECK" ]; then
    echo
    echo "ERROR: HOST CHECK output nem jött létre."
    exit 1
fi


# ============================================================
# HOST CHECK OUTPUT FELDOLGOZÁSA
# ============================================================

awk -v mapfile="$HOST_MAP" '

BEGIN {

    FS="[ \t]+"

    # --------------------------------------------------------
    # IP -> HOST
    # --------------------------------------------------------

    while ((getline line < mapfile) > 0) {

        split(line, a, "\t")

        ip_by_host[a[2]]=a[1]
    }

    close(mapfile)

    current_host=""
    current_group=""
}


# ------------------------------------------------------------
# HOST CHECK
# ------------------------------------------------------------

/^SRPClient> CONFIG OBJECT HOST CHECK name=/ {

    prefix="SRPClient> CONFIG OBJECT HOST CHECK name="

    current_host=substr($0, length(prefix)+1)

    current_group=""

    next
}


# ------------------------------------------------------------
# GROUP SECTION
# ------------------------------------------------------------

/^\[Group\]/ {

    in_group=1

    next
}


/^\[Configuration\]/ {

    in_group=0

    next
}


/^Group=/ {

    group=$0

    group=substr(group, 7)

    if (group != "") {
        current_group=group
    }

    next
}


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

/^module=/ {

    module=""
    slot=""
    line_no=""
    ruleid=""

    for (i=1; i<=NF; i++) {

        x=$i

        if (index(x, "module=") == 1) {
            module=substr(x, 8)
        }

        if (index(x, "slot=") == 1) {
            slot=substr(x, 6)
        }

        if (index(x, "line=") == 1) {
            line_no=substr(x, 6)
        }

        if (index(x, "ruleid=") == 1) {
            ruleid=substr(x, 8)
        }
    }


    if (current_host != "" && ruleid != "") {

        ip=ip_by_host[current_host]

        key=ip SUBSEP \
            current_host SUBSEP \
            current_group SUBSEP \
            module SUBSEP \
            slot SUBSEP \
            line_no SUBSEP \
            ruleid


        if (!(key in seen)) {

            print \
                ip "\t" \
                current_host "\t" \
                current_group "\t" \
                module "\t" \
                slot "\t" \
                line_no "\t" \
                ruleid

            seen[key]=1
        }
    }

    next
}

' "$OUT_CHECK" > "$RULE_MAP"


# ------------------------------------------------------------
# Rule ID eredmények
# ------------------------------------------------------------

if [ ! -s "$RULE_MAP" ]; then

    echo
    echo "A HOST CHECK nem talált firewall szabályt."

    exit 0
fi


echo
echo "Talált ruleid-k:"
echo "----------------"

cat "$RULE_MAP"


# ============================================================
# 3. FILTER / NAT RULE LOOKUP
# ============================================================

echo
echo "============================================================"
echo "3. FILTER / NAT RULE LOOKUP"
echo "============================================================"

rm -f "$CMD_RULE"
rm -f "$OUT_RULE"


# ------------------------------------------------------------
# Rule lookup parancsok előállítása
#
# Ugyanazt a module + ruleid kombinációt csak egyszer kérjük.
# ------------------------------------------------------------

awk -F '        ' '

{
    module=$4
    ruleid=$7


    # --------------------------------------------------------
    # FILTER
    # --------------------------------------------------------

    if (module == "Filter") {
        type="filter"
    }
    else if (module == "filter") {
        type="filter"
    }
    else if (module == "FILTER") {
        type="filter"
    }


    # --------------------------------------------------------
    # NAT
    # --------------------------------------------------------

    else if (module == "NAT") {
        type="nat"
    }
    else if (module == "Nat") {
        type="nat"
    }
    else if (module == "nat") {
        type="nat"
    }


    # --------------------------------------------------------
    # Ismeretlen module
    # --------------------------------------------------------

    else {
        type="filter"
    }


    key=type ":" ruleid


    if (!(key in seen)) {

        print "CONFIG FILTER EXPLICIT index=1 type=" type " start=0 search=\"*ruleid=" ruleid "*\""

        seen[key]=1
    }
}

' "$RULE_MAP" > "$CMD_RULE"


if [ ! -s "$CMD_RULE" ]; then

    echo
    echo "Nincs lekérdezhető szabály."

    exit 0
fi


echo
echo "Lekérdezendő szabályok:"
echo "-----------------------"

cat "$CMD_RULE"


# ------------------------------------------------------------
# Rule lookup
# ------------------------------------------------------------

nsrpc \
    -c "$CMD_RULE" \
    -t "$TARGET_FILE" \
    -l "$OUT_RULE" \
    >/dev/null 2>&1


if [ ! -f "$OUT_RULE" ]; then

    echo
    echo "ERROR: FILTER/NAT output nem jött létre."

    exit 1
fi


# ============================================================
# 4. RULE -> CSV
#
# CSV:
#
# LINE;RULEID;POSITION;RULE
#
# Egy module + ruleid -> egy CSV sor.
# ============================================================

echo
echo "============================================================"
echo "4. FILTER / NAT RULE FELDOLGOZÁS"
echo "============================================================"


rm -f "$OUTPUT_FILE"

echo 'LINE;RULEID;POSITION;RULE' > "$OUTPUT_FILE"


awk -v rulesfile="$RULE_MAP" '

BEGIN {

    FS="[ \t]+"


    # --------------------------------------------------------
    # RULE_MAP betöltése
    #
    # Egy module + ruleid kombinációhoz csak az első
    # előfordulást tartjuk meg.
    # --------------------------------------------------------

    while ((getline line < rulesfile) > 0) {

        split(line, a, "\t")

        module=a[4]
        line_no=a[6]
        ruleid=a[7]

        key=module SUBSEP ruleid


        if (!(key in seen_rule)) {

            r_line[key]=line_no
            r_ruleid[key]=ruleid

            seen_rule[key]=1
        }
    }

    close(rulesfile)


    current_type=""
    current_ruleid=""
}


# ============================================================
# EXPLICIT RULE COMMAND
# ============================================================

/^SRPClient> CONFIG FILTER EXPLICIT/ {

    current_type=""
    current_ruleid=""


    if (index($0, "type=filter") > 0) {
        current_type="Filter"
    }


    if (index($0, "type=nat") > 0) {
        current_type="NAT"
    }


    # --------------------------------------------------------
    # search="*ruleid=5*"
    # --------------------------------------------------------

    x=$0

    p=index(x, "ruleid=")


    if (p > 0) {

        x=substr(x, p+7)

        q=index(x, "*")


        if (q > 0) {
            current_ruleid=substr(x, 1, q-1)
        }
        else {
            current_ruleid=x
        }
    }


    next
}


# ============================================================
# RULE RESULT
# ============================================================

/^position=.*ruleid=/ {

    position=""
    ruleid=""
    ruletext=$0


    # --------------------------------------------------------
    # POSITION
    # --------------------------------------------------------

    x=$0


    if (index(x, "position=") == 1) {

        x=substr(x, 10)

        p=index(x, ";")


        if (p > 0) {
            position=substr(x, 1, p-1)
        }
    }


    # --------------------------------------------------------
    # RULEID
    # --------------------------------------------------------

    x=$0

    p=index(x, "ruleid=")


    if (p > 0) {

        x=substr(x, p+7)

        q=index(x, ":")


        if (q > 0) {
            ruleid=substr(x, 1, q-1)
        }
    }


    # --------------------------------------------------------
    # "position=N; " eltávolítása
    # --------------------------------------------------------

    p=index(ruletext, ";")


    if (p > 0) {
        ruletext=substr(ruletext, p+2)
    }


    # --------------------------------------------------------
    # module + ruleid alapján
    # --------------------------------------------------------

    key=current_type SUBSEP ruleid


    if (key in seen_rule) {

        print \
            r_line[key] ";" \
            r_ruleid[key] ";" \
            position ";" \
            ruletext
    }
}

' "$OUT_RULE" >> "$OUTPUT_FILE"


# ============================================================
# KÉSZ
# ============================================================

echo
echo "============================================================"
echo "Kész."
echo "Eredmény: $OUTPUT_FILE"
echo "============================================================"


echo
echo "CSV:"
echo "------------------------------------------------------------"

cat "$OUTPUT_FILE"

echo
