<html>
<head>
    <title>Statistics</title>
    <style>
#errordist {
        float:  left;
        width:  500px;
    }
#statistics {
        float:  right;
        width:  500px;
    }
#globalstats {
        padding:            2px;
        border-style:       solid;
        border-color:       #000;
        border-collapse:    collapse;
        width:              100%;
    }
#fuzzers {
        clear:  both;
    }
#notable_results {
        background-color:   red;
        color:              white;
    }
    </style>
</head>
<body>
<h1>iknowthis Statistics Generated on <?cs var:Page.date ?></h1>
<div id="global">
    <div id="errordist">
        <img src="http://chart.apis.google.com/chart?cht=p&chs=800x300&chl=<?cs each:i = Global.errors ?><?cs var:i.description ?>|<?cs /each ?>&chd=t:<?cs each:i = Global.errors ?><?cs var:i.count ?>,<?cs /each ?>0">
    </div>
    <div id="statistics">
        <table id="globalstats">
            <tr>
                <thead>Global Statistics</thead>
            <tr>
            <tr>
                <td>Total Fuzzers</td>
                <td><?cs var:Global.num_fuzzers ?></td>
            </tr>
            <tr>
                <td>Total Executions</td>
                <td>
                    <?cs var:Global.total_executions ?> (<?cs var:Global.total_successes ?> Success / <?cs var:Global.total_failures ?> Failure)
                </td>
            </tr>
            <?cs each:i = Global.errors ?>
                <tr>
                    <td><?cs var:i.description ?></td>
                    <td><?cs var:i.count ?></td>
                </tr>
            <?cs /each ?>
        </table>
    </div>
    <div id="fuzzers">
        <table>
            <tr>
                <thead>Fuzzer Statistics</thead>
            </tr>
            <tr>
                <td>Slowest Fuzzer</td>
                <td><?cs var:Global.slowest_fuzzer.name ?> (<?cs var:Global.slowest_fuzzer.speed ?> us)</td>
            </tr>
            <tr>
                <td>Fastest Fuzzer</td>
                <td><?cs var:Global.fastest_fuzzer.name ?> (<?cs var:Global.fastest_fuzzer.speed ?> us)</td>
            </tr>
        </table>
    <div>
</div>

<div id="notable_results">
    <table>
        <tr>
            <thead>The following system call numbers do not have fuzzers defined.</thead>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_missing ?>
                <?cs var:i.number ?>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <thead>The following system calls have fuzzers defined, but are disabled.</thead>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_disabled ?>
                <?cs var:i.name ?>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <thead>The following fuzzers always fail, but are not marked SYS_FAIL.</thead>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_always_fails ?>
                <?cs var:i.name ?>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <thead>The following fuzzers always return the same value, but are not marked SYS_BORING.</thead>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_always_same ?>
                <?cs var:i.name ?>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <thead>The following fuzzers are marked SYS_BORING, but are returning multiple values.</thead>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_not_boring ?>
                <?cs var:i.name ?>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <thead>The following fuzzers are marked SYS_FAIL, but have returned success.</thead>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_not_failing ?>
                <?cs var:i.name ?>,
        <?cs /each ?>
        </td></tr>
    </table>
</div>
<div id="individual_fuzzers">
    <?cs each:i = Fuzzer ?>
    <table>
        <tr>
            <td><thead><?cs var:i.Name ?></thead></td>
        </tr>
        <tr>
            <td>Total</td>
            <td><?cs var:i.Total ?></td>
        </tr>
        <tr>
            <td>Failures</td>
            <td><?cs var:i.Failures ?></td>
        </tr>
        <tr>
        <td>
        <table>
            <tr>Error Distribution</tr>
            <?cs each:err = i.Errors ?>
                <tr>
                    <td><?cs var:err.error ?>
                    <td><?cs var:err.count ?>
                </tr>
            <?cs /each ?>
        </table>
        </td>
        </tr>
    </table>
    <?cs /each ?>
</div>
</body>
</html>
