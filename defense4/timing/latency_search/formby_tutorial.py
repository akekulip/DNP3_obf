"""Plain-English tutorial built from the frozen Formby evaluation and timing data."""
from __future__ import annotations

import csv
from pathlib import Path
from xml.sax.saxutils import escape

import numpy as np
from matplotlib import pyplot as plt
from matplotlib.patches import FancyBboxPatch
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, Spacer, Table, TableStyle

OPS = ("READ", "SELECT", "OPERATE")
MODEL_NAMES = {"ff_ann": "FF-ANN", "multinomial_nb": "Naive Bayes"}
OP_COLORS = {"READ": "#0072B2", "SELECT": "#D55E00", "OPERATE": "#009E73"}


def timing_data(csv_path, out):
    groups = {}
    with Path(csv_path).open() as stream:
        for row in csv.DictReader(stream):
            if int(row["replicate"]) < 40:
                continue
            policy = "native" if row["arm"] == "native" else row["policy_name"]
            labels = [row["txn_class"]]
            if row["txn_class"] in ("SELECT", "OPERATE"):
                labels.append("SBO")
            for label in labels:
                for metric in ("ack_ms", "clrt_ms", "rt_ms"):
                    groups.setdefault((policy, label, metric), []).append(float(row[metric]))
    stats = {}
    for key, values in groups.items():
        a = np.asarray(values)
        stats[key] = dict(n=len(a), mean=float(a.mean()), median=float(np.median(a)),
                          sd=float(a.std(ddof=1)) if len(a) > 1 else None,
                          variance=float(a.var(ddof=1)) if len(a) > 1 else None,
                          p95=float(np.quantile(a, .95)), p99=float(np.quantile(a, .99)),
                          maximum=float(a.max()))
    with (out / "tutorial_timing_statistics.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["policy", "operation", "metric", "n",
            "mean", "median", "sd", "variance", "p95", "p99", "maximum"])
        writer.writeheader()
        for (policy, operation, metric), values in sorted(stats.items()):
            writer.writerow(dict(policy=policy, operation=operation, metric=metric, **values))
    return stats


def timing_figures(stats, quality, policies, out):
    delays = [int(p[2:].split("_", 1)[0]) for p in policies]
    fig, axes = plt.subplots(1, 2, figsize=(7.15, 3.1))
    for op in OPS:
        values = [quality["policies"][p]["heldout_timing"][op] for p in policies]
        axes[0].plot(delays, [v["rt_ms"]["median_ms"] for v in values], "o-",
                     color=OP_COLORS[op], label=op)
        axes[1].plot(delays, [v["added_pooled_median_ms"] for v in values], "o-",
                     color=OP_COLORS[op], label=op)
    for ax, title, ylabel in zip(axes, ("Observed total response time", "Increase over matched Timing OFF"),
            ("Median request-to-response time (ms)", "Difference of pooled medians (ms)")):
        ax.set_title(title, fontsize=9)
        ax.set_xlabel("Configured $D_A$ center (ms)", fontsize=8)
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_xticks(delays)
        ax.grid(axis="y", alpha=.25)
        ax.spines[["top", "right"]].set_visible(False)
    fig.legend(*axes[0].get_legend_handles_labels(), loc="lower center", ncol=3, frameon=False)
    fig.tight_layout(rect=(0, .12, 1, 1))
    for ext in ("pdf", "png"):
        fig.savefig(out / f"tutorial_latency.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(7.15, 2.6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 3.2)
    ax.axis("off")
    for x, text in ((.1, "Incoming packet\nmaster or relay"),
                    (2.7, "Ingress\n7 match-action\nstages"),
                    (5.3, "Traffic manager\nqueues and\nscheduler"),
                    (7.9, "Egress\nselected\noutput port")):
        ax.add_patch(FancyBboxPatch((x, 1.9), 2, .9, boxstyle="round,pad=.03",
                                   facecolor="#e8edf2", edgecolor="#52606d"))
        ax.text(x + 1, 2.35, text, ha="center", va="center", fontsize=8)
    for x in (2.1, 4.7, 7.3):
        ax.annotate("", xy=(x + .55, 2.35), xytext=(x + .04, 2.35),
                    arrowprops=dict(arrowstyle="->", color="#52606d"))
    ax.annotate("", xy=(10.6, 2.35), xytext=(9.94, 2.35),
                arrowprops=dict(arrowstyle="->", color="#52606d"))
    ax.text(11.25, 2.35, "Master\nor relay", ha="center", va="center", fontsize=8)
    ax.plot([8.9, 8.9, 3.7, 3.7], [1.88, .55, .55, 1.35], color="#0072B2", lw=1.2)
    ax.annotate("", xy=(3.7, 1.88), xytext=(3.7, 1.35),
                arrowprops=dict(arrowstyle="->", color="#0072B2"))
    ax.text(6.1, .08, "Loopback via dp8 or dp10 returns a dequeued packet to ingress", ha="center", fontsize=8)
    ax.set_title("Packet processing and queue service are separate steps", fontsize=10)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(out / f"tutorial_packet_path.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(7.15, 3.1))
    for op in OPS:
        for ax, metric in zip(axes, ("sd", "variance")):
            ax.plot(delays, [stats[p, op, "clrt_ms"][metric] for p in policies], "o-",
                    color=OP_COLORS[op], label=op)
    for ax, title, ylabel in zip(axes, ("Spread in the observed CLRT", "Squared spread in the observed CLRT"),
            ("CLRT standard deviation (ms)", "CLRT sample variance (ms²)")):
        ax.set_title(title, fontsize=9)
        ax.set_xlabel("Configured $D_A$ center (ms)", fontsize=8)
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_xticks(delays)
        ax.grid(axis="y", alpha=.25)
        ax.spines[["top", "right"]].set_visible(False)
    fig.legend(*axes[0].get_legend_handles_labels(), loc="lower center", ncol=3, frameon=False)
    fig.tight_layout(rect=(0, .12, 1, 1))
    for ext in ("pdf", "png"):
        fig.savefig(out / f"tutorial_clrt_spread.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)


def build_story(summary, quality, csv_path, out, styles, policies, distribution_tail, confusion):
    stats = timing_data(csv_path, out)
    for policy in policies:
        for op in OPS:
            for metric in ("ack_ms", "clrt_ms", "rt_ms"):
                saved = quality["policies"][policy]["heldout_timing"][op][metric]
                observed = stats[policy, op, metric]
                for field, source_field in (("n", "n"), ("mean", "mean_ms"),
                        ("median", "median_ms"), ("sd", "sd_ms"),
                        ("variance", "variance_ms2"), ("p99", "p99_ms")):
                    if not np.isclose(observed[field], saved[source_field], rtol=1e-10, atol=1e-10):
                        raise ValueError(f"tutorial timing differs from saved report: {policy}/{op}/{metric}/{field}")
    timing_figures(stats, quality, policies, out)
    records = {(r["task"], r["feature"], r["model"], r["scenario"], r["policy"], r["pool_size"]): r
               for r in summary["results"]}
    styles.add(ParagraphStyle(name="TutorialBody", fontName="Helvetica", fontSize=10.3,
                              leading=14.5, spaceAfter=9))
    styles.add(ParagraphStyle(name="TutorialCell", fontName="Helvetica", fontSize=8,
                              leading=10.5))
    story = []

    def para(text):
        story.append(Paragraph(text, styles["TutorialBody"]))

    def page(title, *paragraphs):
        if story:
            story.append(PageBreak())
        story.append(Paragraph(title, styles["Section"]))
        for text in paragraphs:
            para(text)

    def heading(text):
        story.append(Paragraph(text, styles["Subsection"]))

    def table(rows, widths=None):
        cells = [[Paragraph(escape(str(cell)).replace("\n", "<br/>"), styles["TutorialCell"])
                  for cell in row] for row in rows]
        widths = widths or [7.1 / len(rows[0])] * len(rows[0])
        t = Table(cells, colWidths=[w * inch for w in widths], repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), .7, colors.HexColor("#91a3b0")),
            ("LINEBELOW", (0, 1), (-1, -1), .25, colors.HexColor("#d6dfe5")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([t, Spacer(1, .12 * inch)])

    def plot(name, height):
        story.append(Image(str(out / name), width=7.1 * inch, height=height * inch))

    def result(model, scenario, policy="native", feature="formby_histogram", pool=20, task="read_sbo"):
        return records[task, feature, model, scenario, policy, pool]

    def pct(value):
        return f"{100 * value:.2f}%"

    def interval(r):
        low, high = r["round_balanced_accuracy_ci95"]
        return f"{100 * low:.2f}–{100 * high:.2f}%"

    source = summary["source"]
    page("Timing obfuscation and attacker classification: a practical tutorial",
         "This guide explains what the switch changes, what the attacker sees, how the two classifiers learn, and what the measurements allow us to conclude. It uses the completed randomized-delay experiment and the Formby-style evaluation. The goal is to make every figure and number understandable before using it in a discussion with Dr. Lin.",
         "The engineering objective has two parts: hide useful timing differences between operations, and add as little response delay as possible. A setting is useful only if it makes the relevant attackers unreliable while keeping the operational cost acceptable. A larger variance, a lower static score, or fewer late responses cannot answer both parts on its own.")
    table([["Evidence", "What this tutorial uses"],
           ["Recorded traffic", f"{source['row_count']:,} matched request/response records in {source['archived_capture_count']} captures"],
           ["Capture span", f"{source['archived_capture_span_hours']:.2f} hours for the whole interleaved campaign"],
           ["Timing settings", "D_A centers: 5, 10, 15, 20 ms. Code D_R center: 1 ms. Both choices randomized."],
           ["Evaluation split", "40 training rounds; 60 later held-out rounds"],
           ["Hardware record", "Seven ingress match-action stages; matching binary hashes before and after collection"],
           ["Recorded completeness", f"{source['missing_primary_responses']} missing primary responses; {source['capture_drops']} reported capture drops"]], [1.55, 5.55])
    para("The main result is a large reduction in the usefulness of the original timing pattern for the frozen static models. The adaptive models retain smaller operation-dependent signals. The detailed sections explain why ordinary accuracy can look fairly high even when those signals are weak, and why this does not establish complete protection.")

    page("How to use this guide",
         "Read Sections 1–4 first to understand the timing and queueing idea. Sections 5–11 explain the data, attackers, machine-learning inputs, and scores. Sections 12–18 walk through the classifier figures and timing distributions. Sections 19–21 compare overhead, target misses and the four delay settings. Sections 22–25 explain the remaining evidence needed for a design decision. Section 26 is a glossary and source guide. The PDF bookmarks link to each section and continuation page.",
         "Three labels keep the evidence clear. <b>Configured</b> means a value selected by the experiment. <b>Measured</b> means calculated from observed packet timestamps or saved classifier outcomes. <b>Estimated</b> means inferred using a model or reference data. A worked example is explicitly illustrative and is not a measured transaction.",
         "Unless a table says otherwise, timing summaries and classification results use the same 60 held-out rounds, numbered 40–99. Counts describing the whole collection use all 100 rounds. Mixing those two populations can make correct numbers appear to disagree.",
         "The word native in figure labels means the experiment's Timing OFF reference. The protected condition means timing obfuscation was enabled. The data are from one relay workload. The classifier labels in this evaluation are operations, rather than identities from a collection of different devices.",
         "Each results section follows the same order: what question the measurement answers, how to read it, what the actual results show, and what that means for the low-overhead objective. The glossary at the end provides short definitions of the technical terms.")

    page("1. What the observer actually measures",
         "A master sends a request. An acknowledgment, or ACK, comes back. The application response arrives later. The packet capture records the request, ACK, and response at the master-facing observation point. These three timestamps define the intervals used by the attacker.")
    table([["Interval", "Calculation", "Meaning"],
           ["ACK time", "ACK timestamp minus request timestamp", "Time from the observed request to its acknowledgment"],
           ["CLRT", "Response timestamp minus ACK timestamp", "The cross-layer response-time interval visible after the acknowledgment"],
           ["Total response time", "Response timestamp minus request timestamp", "How long the full observed request-to-response exchange took"]], [1.2, 2.35, 3.55])
    para("For the same matched transaction, total response time equals ACK time plus CLRT. This identity is useful for checking the extraction. It also explains why delaying the ACK can change CLRT even when the response receives little or no extra waiting.")
    para("Illustrative example: a request is observed at 0 ms, its ACK at 1 ms, and its response at 4 ms. ACK time is 1 ms, CLRT is 3 ms, and total response time is 4 ms. If the visible ACK and response instead appear at 5 ms and 6 ms, CLRT becomes 1 ms and total response time becomes 6 ms. The attacker sees a smaller gap while the master waits longer overall.")
    para("The measured CLRT includes everything between these two observed packets. It can contain device processing, transport behavior, switch waiting, and other timing effects. It is a timing signature. It is not a direct stopwatch measurement of the relay's physical actuation.")

    page("2. What D_A and D_R mean in this experiment",
         "Here, D_A names the configured ACK timing setting. The field called D_R in this experiment's code names the chosen ACK-to-response gap, also called the configured new CLRT. Its center is 1 ms. The manuscript has used D_R for a different response-latency quantity; the repository's NOTATION_MAPPING.md records that distinction. Throughout this tutorial, 'code D_R' means the chosen gap, not a measured response hold.",
         "A center is the middle of the configured random choices. It does not mean every packet uses exactly that value. The experiment chooses from four ACK offsets around each D_A center and four gap values around the 1 ms center. The gap choices are approximately 0.500, 0.833, 1.167, and 1.500 ms. Joint choices produce 16 ACK/gap combinations.",
         "The nominal combined centers are therefore 6, 11, 16, and 21 ms. These are timing settings. They are not the added latency of every transaction, and they are not a guarantee that every measured response arrives by that time. An already late response and the path around the switch can produce a larger observed interval.")
    table([["D_A center", "Code D_R center", "Sum of centers", "Why test it?"],
           ["5 ms", "1 ms", "6 ms", "Lowest configured wait in this comparison"],
           ["10 ms", "1 ms", "11 ms", "More room for slower responses"],
           ["15 ms", "1 ms", "16 ms", "Further reduce deadline overruns"],
           ["20 ms", "1 ms", "21 ms", "Largest tested wait; highest delay cost"]], [1.1, 1.3, 1.25, 3.45])
    para("The exact random choices are quantized by the timing implementation. Rounded labels such as 0.500 ms are for reading; the archived timing plans retain the exact values. Later sections separate the variance of these chosen values from the variance of the observed CLRT.")
    para("For this run, all 800 fixed configuration readbacks set anchor_req to 1. The release deadlines are measured from the request's arrival at switch ingress: request time plus selected D_A for the ACK, and request time plus selected D_A plus selected code D_R for the response. The ideal difference is the selected gap. The master-facing capture uses a different observation point and includes path and queue-release effects. Older ACK-anchored descriptions do not describe this run.")

    page("3. How queueing implements the idea",
         "The ingress pipeline recognizes a packet, looks up the relevant transaction state, and decides whether to forward, hold, block, or drop it. The traffic manager stores packets in queues and schedules service. The egress path sends a scheduled packet to its next destination. A loopback path can return it to ingress for another decision.",
         "A blocker is a control packet that uses a higher-priority queue. While blocking is active, it takes service ahead of the held packet. When ingress sees that the release condition has been met, it stops the corresponding blocking activity. The held packet can then receive service and continue. This makes the queueing delay much larger than the time to execute a single pipeline pass.",
         "Blocker packets circulate while the original ACK or response waits in its hold queue. Once dequeued, the original packet returns through ingress for release processing. The original packet does not need to circulate continuously while it is waiting.",
         "ACKs and responses use the dp8 loopback path. The ACK blocker and held ACK use queue IDs 7 and 6. The response blocker and held response use queue IDs 5 and 4. OPERATE holding uses the separate dp10 loopback path, with blocker queue 3 and held-command queue 2. These numbers are configured queue identifiers; the scheduler configuration gives the blocker queues their priority.",
         "The separate OPERATE path matters because its command can be held before reaching the relay. An OPERATE response therefore cannot be explained merely as a READ response with the same response queue. The capture shows the final master-facing intervals, while the relay-facing command release remains unobserved.",
         "Seven ingress stages means seven compiler-allocated match-action stages in this binary. It does not mean seven milliseconds of delay or seven distinct queues. A looped packet re-enters ingress, so stage count alone does not state the number of passes, queue residence time, or traffic-manager load. The identity records report zero allocated egress match-action stages; egress transmission still exists.")

    page("3 continued. What goes into the seven stages")
    plot("tutorial_packet_path.png", 2.6)
    table([["Stage", "Job in this compiled program", "Example table"],
           [0, "Recognize session, load policy, build expected ACK number", "tbl_session / tbl_bor_params"],
           [1, "Track requests and select random timing parameters", "tbl_random_deadlines"],
           [2, "Authorize response; calculate candidate deadlines and OPERATE hold", "tbl_resp_authorise / tbl_bor_codebook"],
           [3, "Choose deadline values for the following state checks", "tbl_select_deadlines"],
           [4, "Read/update state and deadlines; check release eligibility", "tbl_state_decode / tbl_hold_ok"],
           [5, "Decide what happens to a fresh or dequeued packet", "tbl_decide_fresh / tbl_decide_deq"],
           [6, "Apply forwarding, holding, blocking or drop; choose port and queue", "tbl_commit"]], [.55, 4.1, 2.45])
    para("This is the final REDO_PHV1 placement in evidence/randomized_sde9132/table_summary.log. The initial eight-stage allocation in that log was superseded. The build manifest's source and binary hashes match the grid run's program_identity.json. Parsing precedes the stages. These descriptions group related tables; a packet uses only the tables applicable to its path.")
    para("The configured OPERATE command hold has choices near 0.25, 0.5, and 1 ms. That hold changes when the request reaches the relay. Estimates based on an unheld Timing OFF request therefore cannot fully predict protected-path response availability.")

    page("4. Late responses: what changes and what can still leak",
         "A response cannot be released before it exists. If it arrives after the relevant blockers have drained, the switch may forward it with little additional response waiting. It can then exceed the chosen timing target. However, its visible CLRT also depends on when the ACK left. The response need not recover its original native CLRT simply because it was not held.",
         "Illustrative example: the native ACK would appear at 1 ms and the response at 9 ms, giving a native CLRT of 8 ms. Suppose obfuscation moves the visible ACK to 5 ms and the response still appears at 9 ms. Its new visible CLRT is 4 ms. The response missed a nominal 6 ms target, but the observer still sees a changed CLRT. This example explains the mechanism; it does not identify the internal history of any captured packet.",
         "Our target-miss diagnostic checks whether the measured request-to-response time exceeds selected_r_ms by more than 1 ms. That selected value is the experiment's recorded sum of selected timing settings. The extra 1 ms is an analysis threshold. It is not the transaction timeout and is not the same as directly observing a response arrive after an internal queue deadline.",
         "There are three different questions: Was a response absent? Was it later than the stated external timing target? Was it available internally while the queue could still hold it? Captures answer the first two. Timing OFF data can estimate the third under assumptions, but cannot label each protected packet as held or unheld.",
         "Late tails still matter. If one operation produces more long CLRT values, the attacker may learn that tail even if all operations share the same main peak. To show that late tails cause classification, we would need an analysis that isolates them while controlling the other features. An association between misses and scores is not that causal test.")

    page("5. What the long run contains",
         f"The collection spans {source['archived_capture_span_hours']:.2f} hours across all settings together. It is not a separate 21-hour experiment for each delay. Each of the 100 acquisition rounds contains four protected blocks and four matched Timing OFF blocks. A block contains 100 READ responses and 100 SBO exchanges, each with one SELECT response and one OPERATE response.",
         "That produces 300 matched request/response records per block, 2,400 per round, and 240,000 over the full run. SELECT and OPERATE remain separate rows when measuring packet timing; the main classification task gives both rows the SBO label.")
    table([["Population", "READ", "SELECT", "OPERATE", "Total rows"],
           ["Full collection", "80,000", "80,000", "80,000", "240,000"],
           ["All Timing OFF test blocks", "24,000", "24,000", "24,000", "72,000"],
           ["One protected setting: test rounds", "6,000", "6,000", "6,000", "18,000"],
           ["Four protected settings: test rounds", "24,000", "24,000", "24,000", "72,000"]], [2.7, 1.1, 1.1, 1.1, 1.1])
    para(f"The full-run quality report records {quality['missing_primary_responses']} missing primary responses, {quality['capture_drops']} capture drops, and {quality['retransmission_flagged_frames']} retransmission-flagged frames. Those are observations within the capture and matching procedure. They do not expose every internal packet copy or establish exactly-once delivery at the relay.")
    para("Rounds 0–39 supply training data. Rounds 40–99 supply the final tests. Keeping these rounds separate prevents a training signature and a test signature from sharing the same acquisition round. It also makes the test later in time, rather than a random mixture of nearby samples.")

    page("6. The static and adaptive attackers",
         "Both attackers here are supervised: training examples have known operation labels. The model learns a relationship between a timing input and READ or SBO. During testing, it sees the input and predicts the label; the evaluation compares its guess with the saved true label.")
    table([["Evaluation", "Training traffic", "Test traffic", "Question"],
           ["Static before", "Timing OFF, rounds 0–39", "Timing OFF, rounds 40–99", "Was there a usable timing pattern originally?"],
           ["Static after", "The same fitted Timing OFF model", "Protected traffic at one D_A, rounds 40–99", "Does the original pattern still work after the defense?"],
           ["Adaptive", "Protected traffic at that D_A, rounds 0–39", "Protected traffic at the same D_A, rounds 40–99", "Can the attacker learn the remaining protected pattern?"]], [1.0, 1.75, 1.9, 2.45])
    para("The adaptive model does not need any pre-obfuscation traffic. It does need labeled protected training examples under this evaluation. It might obtain labels in a controlled environment or through known operations; that acquisition process is an assumption, not something these captures demonstrate. An attacker with only unlabeled recordings would require an additional labeling or clustering method.")
    para("Adaptive here means retraining for a protected setting. It does not mean the model updates itself on every test packet, changes the defense, or knows the selected random delay for each transaction. Separate models are trained for the four settings, so this is a test of an attacker familiar with the setting it encounters.")
    para("The native point repeated in both columns of the Formby-style figure is the same static-before reference. It helps compare the loss of the original timing signal. It is not a separate adaptive model trained on native traffic.")

    page("7. From response times to a classifier input",
         "A classifier receives numbers, not the plotted picture. A histogram input counts how many CLRT observations fall into each time interval, or bin. The interval is on the x-axis; its count is the corresponding feature value. The collection of counts is the signature given to the model.",
         "Illustrative example: four CLRTs are 0.6, 0.7, 1.1, and 1.4 ms. With illustrative bins 0–1, 1–2, and above 2 ms, their signature is [2, 2, 0]. This example uses three bins only to show the idea. The actual evaluator uses 200: 199 equally wide bins from zero to a bound H, plus one bin for values above H.",
         "H is the largest CLRT in the relevant training population. The static model keeps its native-training H when it sees protected test traffic. Each adaptive model learns H from its protected training population. Values above H go into the overflow bin, so the test tail is retained without choosing bin widths from test results.",
         "A pool size of 20 means one classification signature contains 20 response CLRT observations. Pools do not overlap or cross block, round, or class boundaries. Pool size 1 supplies less distribution information; pool sizes 5 and 20 can reveal a pattern repeated over more observations.",
         "For the main task, a pool of 20 SBO response observations can include SELECT and OPERATE response intervals. It is not automatically 20 complete SBO commands. The evaluator groups observations by their known true class before building a signature. That is a controlled assumption about collecting homogeneous examples, not a demonstration of finding the operation boundaries in arbitrary mixed traffic.")

    page("8. The second input: ACK time plus CLRT",
         "The histogram asks what the CLRT distribution alone reveals. The ACK+CLRT input also lets the model use the visible request-to-ACK interval. For one response, that is two numbers. For a larger pool, the evaluator gives the mean, standard deviation, minimum, and maximum of each interval, making eight numbers in total.",
         "The standard deviation used as an input feature divides squared deviations by the pool size N. The descriptive sample-variance tables later use N−1. Both conventions are defined and used consistently; their different denominators should not be mistaken for different underlying packet timings.",
         "This matters because two operations can have similar CLRT peaks and still differ in ACK behavior. They can also differ in the smallest or largest times within a pool. A model may exploit those differences even if the means look almost identical.",
         "The summary input loses some distribution detail: two different shapes can share a mean and standard deviation. The histogram loses exact within-bin positions and ordering. Comparing the two inputs checks two different views of the observable timing. Neither is a complete test of everything an observer could extract.",
         "The selected random ACK/gap values recorded by the experiment are used for timing diagnostics, not as model input features. These two input families also exclude request cadence as a feature. That limits the claim: low scores here do not establish that request spacing or other protocol information is hidden.",
         "Naive Bayes on histogram counts follows its count-data interpretation. Using the same model on nonnegative ACK/CLRT summary values is an additional adapted probe. A weak score for that adapted probe is less persuasive if its Timing OFF baseline was weak already. Always establish that the model had a usable original signal.")

    page("9. How the two machine-learning models learn",
         "The FF-ANN is a feed-forward artificial neural network with one hidden layer. Each hidden unit combines the input numbers using learned weights. The output scores support a class decision. Training adjusts the weights so known training examples receive the correct label. Backpropagation calculates how each weight contributed to the error.",
         "Before the network, the pipeline fills any missing feature with a training median and standardizes the inputs using training means and scales. This avoids letting a large numerical scale dominate merely because of its units. The hidden-layer choices are 32 or 100 units. The regularization choices are 0.0001 or 0.01; regularization discourages unnecessarily large weights.",
         "The saved implementation uses Adam optimization, a maximum of 300 training iterations, and early stopping after 12 checks without enough improvement. These are training settings, not measured switch behavior. Early stopping uses an internal training-data validation split. The external tuning folds are grouped by acquisition round, but that internal split is not grouped; it stays inside the training population and does not use the final 60 test rounds.",
         "Multinomial naive Bayes estimates which histogram bins are likely under each class. It combines evidence from the bin counts and the class frequencies to choose a label. Its independence assumption is a simplification of how features relate. Smoothing prevents an unseen training bin from making a class probability zero; tested smoothing values are 0.1, 1, and 10.",
         "Five-fold grouped cross-validation selects the settings using only the 40 training rounds. A fold holds out whole training rounds while the others fit the model. Balanced accuracy is the tuning score. The selected configuration is then fitted to the training data and evaluated on the separate final test rounds. These reproduce the classifier families discussed by Formby, with documented local choices; they are not a claim of identical unpublished training details.")

    page("9 continued. Training size and histogram resolution",
         "Native training uses 2,400 READ/SBO signatures at pool 20: 800 READ and 1,600 SBO. A protected setting uses 600 training signatures: 200 READ and 400 SBO. Both cover 40 rounds, but the native model gets four times as many examples. Differences between its original score and the adaptive score therefore combine the timing change with a difference in training-set size. A size-matched comparison would isolate those factors more closely.",
         "The histogram bound also changes with the training population. A long training outlier makes all 199 regular bins wider. The table shows the actual bound H and regular-bin width for the main task. Static-after always keeps the native row's binning.")
    table([["Training condition", "H (ms)", "Regular-bin width H/199 (ms)"],
           *[["Timing OFF" if p == "native" else f"D_A={p[2:].split('_', 1)[0]} ms",
              f"{result('ff_ann', 'static_before' if p == 'native' else 'adaptive', p)['histogram_h_ms']:.6f}",
              f"{result('ff_ann', 'static_before' if p == 'native' else 'adaptive', p)['histogram_h_ms']/199:.6f}"]
             for p in ("native", *policies)]], [2.0, 2.0, 3.1])
    heading("Selected model settings for the main histogram comparison")
    rows = [["Training condition", "FF-ANN units / regularization", "Naive Bayes smoothing"]]
    for policy in ("native", *policies):
        scenario = "static_before" if policy == "native" else "adaptive"
        ann = result("ff_ann", scenario, policy)["chosen_parameters"]
        nb = result("multinomial_nb", scenario, policy)["chosen_parameters"]
        rows.append(["Timing OFF" if policy == "native" else f"D_A={policy[2:].split('_', 1)[0]} ms",
                     f"{ann['mlp__hidden_layer_sizes'][0]} / {ann['mlp__alpha']}", nb["nb__alpha"]])
    table(rows, [2.0, 2.8, 2.3])
    para("The numerical settings were selected inside the training rounds. This table records what was fitted; the held-out results were not used to choose these parameters. The full results file retains settings for the other tasks, feature inputs and pool sizes too.")

    page("10. Accuracy, precision, and recall: a worked example",
         "Suppose one test round has five READ signatures and ten SBO signatures. The model gets two READs right and labels the other three as SBO. It gets nine SBOs right and labels one as READ. The following confusion matrix records those guesses. This is an illustrative example, not a result from the run.")
    table([["True operation", "Predicted READ", "Predicted SBO"], ["READ", 2, 3], ["SBO", 1, 9]], [2.5, 2.3, 2.3])
    para("<b>Accuracy</b> asks how many guesses were correct overall: (2 + 9) / 15 = 73.3%. Because SBO contributes twice as many examples, it contributes twice as much to this score.")
    para("<b>READ recall</b> asks how many real READ examples the model found: 2 / 5 = 40%. <b>SBO recall</b> is 9 / 10 = 90%. Balanced accuracy gives the two classes equal weight: (40% + 90%) / 2 = 65%. Mean recall across the two classes, often called macro recall, has the same value.")
    para("<b>READ precision</b> asks how many READ predictions were correct: 2 / (2 + 1) = 66.7%. <b>SBO precision</b> is 9 / (9 + 3) = 75%. Mean precision gives the two class precision values equal weight: 70.8%. Precision asks whether to trust a predicted label; recall asks how many real examples of that label were found.")
    para("Always guessing SBO gives 10 / 15 = 66.7% accuracy, READ recall 0%, SBO recall 100%, and balanced accuracy 50%. Thus an adaptive accuracy near 67% can largely reflect the class mix. For this task, 50% balanced accuracy is the no-discrimination reference. For the three-class diagnostic it is one third.")

    page("11. What mean, minimum, and uncertainty mean",
         "Each model is scored separately in each of the 60 held-out rounds. Mean accuracy averages the 60 round accuracies. Minimum accuracy is the lowest observed round accuracy. Mean precision and mean recall average the class scores across the rounds. Minimum precision and minimum recall take the lowest class score in any round: 120 class-round scores for READ versus SBO.",
         "These minima are deliberately strict, and their units of aggregation differ. Minimum accuracy concerns a whole round. Minimum recall concerns one class in one round. A zero minimum recall means that class was completely missed in at least one round. Zero minimum precision can also occur because the classifier never predicted that class; the scoring code assigns zero when precision's denominator is zero.",
         "Per-policy protected rounds contain five READ and ten SBO signatures at pool 20. The native reference combines four OFF blocks and contains 20 READ and 40 SBO signatures per round. Across all test rounds that is 900 protected signatures per setting versus 3,600 native signatures. Protected minima are noisier because each round contains fewer examples. They should not be read as equally precise estimates of a worst future case.",
         "Pooled precision is another summary: it adds all correct predictions and all predictions for a class over the test set, then divides. The mean of round precisions instead computes each ratio first and averages. Those answers can differ, especially when a round makes no predictions for one class. The figure uses round means; per_class_metrics.csv also retains pooled precision.",
         "The balanced-accuracy error bars resample the held-out rounds 5,000 times. Their 95% interval describes variation under that resampling procedure for the fitted model. It does not include every future relay, a fresh training seed, or every possible classifier. The intervals are per result, without a joint correction across all the settings and models. The minimum lines in the other figure are not confidence bounds.")

    page("12. First read the overall attacker figure")
    plot("performance_by_delay.png", 4.75)
    para("The top row is READ versus SBO. The bottom row separates READ, SELECT, and OPERATE. The left column uses ACK+CLRT summaries; the right uses CLRT histograms. The vertical axis is balanced accuracy, so compare binary results with 0.5 and three-class results with 1/3.")
    para("Color identifies the classifier. Dashed circles are the unchanged static model on protected traffic. Solid squares are the adaptive model trained on protected traffic. Dotted horizontal lines are each classifier's Timing OFF reference. The error bars describe round-resampling uncertainty.")
    para("Start with the dotted baseline to establish that an original clue existed. Then compare static and adaptive at the same setting. A large static drop shows that the old model transfers poorly. Adaptive recovery shows that learning from protected samples can recover some signal. Neither comparison directly measures physical actuation time or device identification.")

    page("13. The Formby Figure 12-style view: static attacker")
    plot("attacker_metrics_static.png", 2.72)
    para("This figure adapts the style of Formby's Fig. 12 for the static attacker. Formby's horizontal axis is detection time. Here the horizontal axis is the configured D_A center, with the code D_R center held at 1 ms. The first shaded point is the same Timing OFF reference used to show that the original timing signal was learnable.")
    para("Blue is accuracy, orange is precision, and green is recall. Solid lines are round means. Dashed lines are observed minima. The two panels show the same traffic with two classifier families: FF-ANN and Naive Bayes.")
    para("There is no single chance line for all six curves. Ordinary accuracy has a 66.67% majority-class baseline in this READ/SBO signature task. Precision depends on what the model predicts. Mean recall is the same as balanced accuracy here, so compare the green mean-recall curve with 50% when asking whether the model is discriminating READ from SBO.")
    para("The static attacker trains on Timing OFF traffic and then applies that frozen model to protected traffic. A large fall from the Timing OFF reference means the original decision rule no longer transfers well. It does not prove that no timing information remains, because an attacker with protected training data is a different case.")

    page("13 continued. The Formby Figure 12-style view: adaptive attacker")
    plot("attacker_metrics_adaptive.png", 2.72)
    para("This figure uses the same metric definitions, but the attacker is adaptive. For each D_A setting, the model trains and tests on protected traffic from that setting, using separate training and held-out rounds. The shaded Timing OFF reference is included only as a reference point; it is not an adaptive model.")
    para("Read ordinary accuracy together with recall. The READ/SBO task has twice as many SBO signatures as READ signatures. A classifier can therefore obtain a high ordinary accuracy by choosing SBO often. Mean recall equals balanced accuracy in this binary task; values near 50% mean weak READ/SBO discrimination, while values above 50% show residual discrimination. Per-class recall and the confusion matrices show whether the model is finding READ as well as SBO.")
    para("Some minimum-precision and minimum-recall lines overlap at zero because both measured minima are zero. This is a shared value, not a missing curve. The combined legacy chart is still regenerated as attacker_metrics_by_da.png, and the next tables give the exact numbers for every point.")

    for model in MODEL_NAMES:
        page(f"13 continued. Exact mean/minimum scores: {MODEL_NAMES[model]}",
             "These are the values plotted in the six-line figure for the main READ/SBO histogram task at pool 20. All scores are percentages. Each cell gives mean / minimum. Accuracy uses round scores; precision and recall minima use individual class-round scores.")
        rows = [["Traffic", "Attacker", "Accuracy mean / min", "Precision mean / min", "Recall mean / min"]]
        cases = [("native", "static_before", "Native reference")]
        cases += [(p, s, label) for p in policies for s, label in
                  (("static_after", "Static"), ("adaptive", "Adaptive"))]
        for policy, scenario, label in cases:
            r = result(model, scenario, policy)
            rows.append(["Timing OFF" if policy == "native" else f"D_A={r['da_ms']:g} ms", label,
                         *[f"{100*r['round_mean_'+metric]:.2f} / {100*r['round_min_'+metric]:.2f}"
                           for metric in ("accuracy", "precision", "recall")]])
        table(rows, [1.15, 1.3, 1.55, 1.55, 1.55])
        para("A zero minimum is a local failure, not failure on every example. A high mean can coexist with a zero minimum because only one class in one round needs to reach zero. Protected READ recall moves in steps of 20 percentage points within a round: there are only five READ signatures. Native READ recall moves in steps of five points because there are 20.")
        para("The means describe typical performance across these rounds; minima expose a weakest observed case. For assessing the defense, also look at how well the attacker succeeds on average and whether its strongest tested input still discriminates. A defense is not established just because the attacker sometimes makes mistakes.")

    page("14. What the static attacker achieves",
         "The static model first learns the Timing OFF operation pattern. We then freeze it and apply it to protected signatures. The table gives the main histogram result at pool 20. Accuracy counts all correct guesses; balanced accuracy gives READ and SBO equal weight.")
    rows = [["Classifier", "Test traffic", "Accuracy", "Balanced accuracy", "READ recall", "SBO recall"]]
    for model in MODEL_NAMES:
        for policy in ("native", *policies):
            r = result(model, "static_before" if policy == "native" else "static_after", policy)
            label = "Timing OFF" if policy == "native" else f"D_A={r['da_ms']:g} ms"
            rows.append([MODEL_NAMES[model], label, pct(r["accuracy"]), pct(r["balanced_accuracy"]),
                         pct(r["per_class"]["READ"]["recall"]), pct(r["per_class"]["SBO"]["recall"])])
    table(rows, [1.0, 1.2, 1.1, 1.3, 1.25, 1.25])
    para("Both histogram classifiers have strong native discrimination. Their protected results show that the original decision rules no longer work reliably. Increasing D_A does not make the score decrease smoothly: the frozen decision boundary reacts to the shifted distribution, not simply to how many responses missed a deadline.")
    para("Below-chance performance deserves care. At D_A=10 ms, the FF-ANN has 44.42% balanced accuracy. In a binary task, reversing every predicted label would mathematically give 55.58%. That reversal was not the tested static attacker and choosing it would require extra knowledge or labeled evidence. It nevertheless shows why a low or inverted score alone does not prove the timing carries no information.")

    page("15. What the adaptive attacker recovers",
         "The adaptive model learns from protected training traffic at the setting it will face. This table again uses the histogram and pool 20. The confidence interval is for balanced accuracy; READ and SBO recalls show which operation the classifier actually finds.")
    rows = [["Model", "D_A", "Accuracy", "Balanced accuracy [95% interval]", "READ recall", "SBO recall"]]
    for model in MODEL_NAMES:
        for policy in policies:
            r = result(model, "adaptive", policy)
            rows.append([MODEL_NAMES[model], f"{r['da_ms']:g}", pct(r["accuracy"]),
                         f"{pct(r['balanced_accuracy'])}\n[{interval(r)}]",
                         pct(r["per_class"]["READ"]["recall"]), pct(r["per_class"]["SBO"]["recall"])])
    table(rows, [1.0, .55, 1.0, 2.05, 1.25, 1.25])
    r = result("ff_ann", "adaptive", policies[0])
    cm = r["confusion_matrix"]
    para(f"At 5 ms, the adaptive FF-ANN correctly labels {cm[0][0]} of 300 READ signatures and {cm[1][1]} of 600 SBO signatures. It mostly chooses SBO. Its {pct(r['accuracy'])} accuracy therefore sounds stronger than its {pct(r['balanced_accuracy'])} balanced accuracy. READ recall is only {pct(r['per_class']['READ']['recall'])}.")
    para("The histogram models retain small positive balanced-accuracy advantages at these tested settings. Each reported pointwise interval lies above 50%, but a statement covering every model and setting requires a joint statistical analysis. The evidence supports substantial degradation of these attackers with residual discrimination; it does not support complete removal of operation information.")

    for policy, path in zip(policies, confusion):
        da = int(policy[2:].split("_", 1)[0])
        page(f"16. Reading the confusion matrices: D_A = {da} ms")
        plot(path.name, 4.3)
        para("The top row uses the main READ-versus-SBO task. The bottom row uses the secondary three-phase task. Read a matrix across each true-class row: the diagonal is correct; the other cells show the wrong predicted labels. Counts and percentages are both shown. These matrices use the FF-ANN histogram input at pool 20.")
        r = result("ff_ann", "adaptive", policy)
        cm = r["confusion_matrix"]
        para(f"For the adaptive binary panel, {cm[0][0]} READ signatures are recognized and {cm[0][1]} are called SBO. Of the SBO signatures, {cm[1][1]} are recognized and {cm[1][0]} are called READ. This explains its balanced accuracy of {pct(r['balanced_accuracy'])} more directly than ordinary accuracy alone.")
        para("The native panels contain four times as many signatures as a protected panel. Compare the row percentages when assessing discrimination, rather than comparing raw counts between panels. A nearly full SBO prediction column means the classifier has a strong preference for SBO; it does not mean it has recovered both operation classes well.")

    page("17. Does more observation or another input help?",
         "The main figure fixes pool size at 20 to show a stable distribution signature. An attacker may instead have one observation or five. The table below reports adaptive balanced accuracy for the histogram across those three pool sizes. Each entry comes from a separately trained model with the corresponding input.")
    rows = [["Model", "D_A (ms)", "Pool 1", "Pool 5", "Pool 20"]]
    for model in MODEL_NAMES:
        for policy in policies:
            rows.append([MODEL_NAMES[model], policy[2:].split("_", 1)[0],
                         *[pct(result(model, "adaptive", policy, pool=pool)["balanced_accuracy"])
                           for pool in (1, 5, 20)]])
    table(rows, [1.25, 1.15, 1.55, 1.55, 1.6])
    para("More observations do not guarantee a higher score for a particular fitted model. Pooling changes the number of training signatures, the amount of information in each signature, and the feature representation. It also lets the attacker learn differences in distribution shape rather than relying on one interval.")
    heading("ACK+CLRT at pool 20")
    rows = [["D_A (ms)", "Adaptive FF-ANN", "Adaptive Naive Bayes"]]
    for policy in policies:
        rows.append([policy[2:].split("_", 1)[0],
                     *[pct(result(m, "adaptive", policy, feature="ack_clrt")["balanced_accuracy"])
                       for m in MODEL_NAMES]])
    table(rows, [1.5, 2.8, 2.8])
    para("For example, at 15 ms the adaptive FF-ANN scores 54.92% with ACK+CLRT and 51.92% with the histogram. These inputs are not nested: they summarize the data differently. The comparison suggests that the histogram result alone understates the tested attack surface, but does not isolate ACK timing as the sole cause.")

    page("18. Timing distributions, standard deviation, and variance")
    plot("clrt_distributions.png", 3.75)
    para("The horizontal axis is measured CLRT in milliseconds. The vertical axis is density: the fraction of observations per millisecond of bin width. A peak says that many responses have similar CLRTs. The area of a bin is its approximate fraction of observations; the height alone is not a packet count. A density can exceed one when the data are concentrated in narrow intervals.")
    para("Blue dashed curves show Timing OFF; orange curves show protected traffic. The SBO row combines the two response phases. The display is zoomed to 0–20 ms. Longer responses remain in the statistics and classifier inputs. The largest excluded fraction in any plotted group is "
         f"{100 * distribution_tail['max_fraction_above_20ms']:.3f}%.")
    para("These plots compare each operation with its own reference. To judge classification, also compare READ with SBO under the same protected setting. Different tails, peak weights, or widths can remain useful even when both operations center near the chosen 1 ms gap.")

    page("18 continued. What exactly has a variance?",
         "A mean CLRT is the average of the observed ACK-to-response intervals. Standard deviation describes their spread around that mean and uses milliseconds. Variance is the average squared spread, with the sample correction used here; its unit is square milliseconds. Variance is the square of standard deviation, not another independent measure.",
         "Illustrative example: three observed CLRTs are 1, 1, and 4 ms. Their mean is 2 ms. Their sample variance is [(1−2)² + (1−2)² + (4−2)²] / (3−1) = 3 ms², and their standard deviation is about 1.73 ms. The one long value matters. A large tail can raise variance while the main peak remains very narrow.",
         "The variance of the configured gap choices is different. The four approximately equally likely code D_R values give a configured population variance of about 0.138871 ms², or SD 0.372654 ms. This is the same design distribution at all four D_A centers. The empirical frequency of actual draws can vary slightly between finite samples.",
         "The measured new-CLRT variance includes that chosen variation plus arrival timing, queue behavior, and the observed tails. Reducing it is helpful only if the resulting class distributions become harder to distinguish. Two tight but separated peaks can be easy to classify. Two wide, nearly identical distributions can be hard to classify. Variance by itself is therefore not a privacy or attacker-success metric.",
         "The following tables use all held-out observations, including long tails, and sample variance with denominator N−1. The native rows pool the four Timing OFF references. SBO statistics combine SELECT and OPERATE observations and are not the variance of a full SELECT-to-OPERATE transaction duration.")
    rows = [["Traffic", "Operation", "N", "Mean CLRT (ms)", "SD (ms)", "Variance (ms²)"]]
    for policy in ("native", *policies):
        for op in ("READ", "SBO"):
            s = stats[policy, op, "clrt_ms"]
            rows.append(["Timing OFF" if policy == "native" else f"D_A={policy[2:].split('_', 1)[0]}",
                         op, f"{s['n']:,}", f"{s['mean']:.3f}", f"{s['sd']:.3f}", f"{s['variance']:.3f}"])
    table(rows, [1.2, .9, .9, 1.4, 1.2, 1.5])

    page("18 continued. Separate the SBO phases when diagnosing spread")
    plot("tutorial_clrt_spread.png", 3.1)
    rows = [["D_A (ms)", "Operation", "Mean CLRT (ms)", "SD (ms)", "Variance (ms²)", "CLRT p99 (ms)"]]
    for policy in policies:
        for op in OPS:
            s = stats[policy, op, "clrt_ms"]
            rows.append([policy[2:].split("_", 1)[0], op, f"{s['mean']:.3f}",
                         f"{s['sd']:.3f}", f"{s['variance']:.3f}", f"{s['p99']:.3f}"])
    table(rows, [.8, 1.0, 1.4, 1.15, 1.4, 1.35])
    para("READ retains a broader tail than the two SBO phases at several settings. Its SD does not decrease monotonically with D_A in this held-out sample. Rare long observations can dominate squared spread. This is a reason to retain the tails and show p99 alongside variance, rather than selecting only the central peak.")

    page("19. The latency cost: total waiting versus added waiting")
    plot("tutorial_latency.png", 3.1)
    para("The left panel shows the measured median request-to-response time. The right panel subtracts the corresponding matched Timing OFF median. The second quantity is a difference between population medians. It is not a direct measurement of how long each individual packet was held, and it is not the median of individually paired packet differences.")
    para("At a configured D_A center of 5 ms and gap center of 1 ms, a measured response around 6.1 ms does not mean the defense added 6.1 ms. The native exchange already takes time. For example, the held-out READ median is about 6.112 ms, and its increase over the matched reference median is about 3.352 ms.")
    para("Increasing D_A gives slow responses more time to become available, but delays the bulk of responses even when they were ready earlier. That is the cost being minimized. The seven-stage count is a resource measurement; these millisecond delays primarily concern the timing policy and queues.")
    para("Median describes a typical exchange. The 95th percentile means 95% of the observed exchanges finish by that value; the 99th percentile has the same interpretation for 99%. Tail percentiles matter because a low typical cost can coexist with occasional long waits.")

    page("19 continued. Measured overhead by operation")
    rows = [["D_A", "Operation", "OFF median (ms)", "Protected median (ms)", "Added median (ms)", "Protected p99 (ms)"]]
    for policy in policies:
        for op in OPS:
            t = quality["policies"][policy]["heldout_timing"][op]
            rows.append([policy[2:].split("_", 1)[0], op, f"{t['native_rt_ms']['median_ms']:.3f}",
                         f"{t['rt_ms']['median_ms']:.3f}", f"{t['added_pooled_median_ms']:.3f}",
                         f"{t['rt_ms']['p99_ms']:.3f}"])
    table(rows, [.6, .95, 1.3, 1.5, 1.35, 1.4])
    para("These rows use the 60 held-out rounds and each setting's matched Timing OFF blocks. This differs from the pooled native reference used to train and test the static classifier. Both comparisons are intentional: the timing comparison matches conditions locally, while the static model uses all available OFF training blocks.")
    para("A p99 near or above another setting's median is not a contradiction. The median describes the middle of a distribution; p99 describes its upper tail. Choosing a setting requires deciding which operational delay measure matters and checking it together with the attacker's strongest relevant score.")

    page("20. How many responses exceeded the target?",
         "The counts below use the saved diagnostic: observed request-to-response time greater than selected_r_ms + 1 ms. Each protected operation contributes 6,000 held-out response records. A response counted here was observed; it was late relative to that diagnostic target rather than missing from the capture.")
    rows = [["D_A (ms)", "Operation", "Responses", "Target misses", "Fraction"]]
    for policy in policies:
        for op in OPS:
            d = summary["delay_policy_diagnostics"][policy][op]
            rows.append([policy[2:].split("_", 1)[0], op, f"{d['heldout_responses']:,}",
                         d["selected_target_miss_count"], pct(d["selected_target_miss_fraction"])])
    table(rows, [1.0, 1.2, 1.5, 1.6, 1.8])
    para("Earlier discussions used figures around 16.6% for responses outside a wait window. A fraction from an earlier run, a Timing OFF availability estimate, and this protected-response target-miss fraction have different numerators and denominators. They should not be substituted for one another. The exact population and threshold above define this table.")
    para("A longer D_A generally helps the scheduling opportunity, but a lower miss rate does not mechanically force a lower classifier score. Operation-specific peak shape, class imbalance, ACK timing, and the model's decision rule can still matter. The miss measurement and the classification measurement answer different questions.")

    page("20 continued. Why coverage estimates differ from target misses",
         "A Timing OFF response later than the D_A center is a simple reference comparison. It does not use the random choice made for a protected transaction, and it ignores the extra chosen gap. The joint-availability estimate instead checks whether an OFF ACK is early enough for a possible selected D_A and whether its response is early enough for that D_A plus the selected gap. It averages those checks over the 16 configured choices.")
    rows = [["D_A", "Operation", "OFF RTT > D_A center", "Estimated joint unavailability", "Measured protected target misses"]]
    for policy in policies:
        for op in ("READ", "SELECT"):
            c = quality["policies"][policy]["heldout_coverage"][op]
            d = summary["delay_policy_diagnostics"][policy][op]
            rows.append([policy[2:].split("_", 1)[0], op, pct(c["beyond_da_center_fraction"]),
                         pct(c["estimated_joint_unavailability"]), pct(d["selected_target_miss_fraction"])])
    table(rows, [.6, .95, 1.6, 1.95, 2.0])
    para("The first two columns of percentages use the matched Timing OFF population. The last uses the actual protected observations. They should not be interpreted as three ways of counting the same packets. Even the joint estimate sees master-facing timestamps, rather than internal switch arrivals, and omits protected queue-state effects.")
    para("OPERATE has an additional command hold before reaching the relay, so native availability is an especially incomplete proxy for that path. This table keeps READ and SELECT separate for the scheduling diagnosis while the main classifier still treats the two SBO response phases as one operation label.")

    page("20 continued. Can the attacker classify only the late responses?",
         "The existing late-subset diagnostic uses individual responses, pool size 1, with the FF-ANN histogram model. It keeps only responses satisfying the greater-than-1-ms target-miss rule. Static and adaptive here refer to the original models trained on their full respective training populations, then applied to this selected test subset.")
    rows = [["D_A", "Task", "Late samples", "Complete-class rounds", "Static BA", "Adaptive BA"]]
    for policy in policies:
        for task, label in (("read_sbo", "READ/SBO"), ("three_class", "Three phases")):
            a = result("ff_ann", "static_fully_late_diagnostic", policy, pool=1, task=task)
            b = result("ff_ann", "adaptive_fully_late_diagnostic", policy, pool=1, task=task)
            enough = min(a["n_rounds"], b["n_rounds"]) >= 5
            rows.append([policy[2:].split("_", 1)[0], label, a["n_samples"], a["n_rounds"],
                         pct(a["balanced_accuracy"]) if enough else "Too few rounds",
                         pct(b["balanced_accuracy"]) if enough else "Too few rounds"])
    table(rows, [.6, 1.1, 1.2, 1.65, 1.3, 1.25])
    para("A complete-class round contains at least one retained observation of every class for that task. The displayed balanced accuracy pools all retained late samples, including those from rounds that lack another class. Complete-class rounds control the separate round summaries and the reporting gate. The table suppresses a score when fewer than five such rounds remain; even five is only a descriptive threshold, not a proof of adequate statistical power.")
    para("This diagnostic does not train a new attacker only on late samples and does not prove that an observer can identify the same subset: the saved target-miss rule uses the selected timing value. It also cannot prove that these packets received no timing change. It is evidence about a selected tail, useful for deciding what to examine next.")

    for policy in policies:
        da = int(policy[2:].split("_", 1)[0])
        page(f"21. Putting the evidence together at D_A = {da} ms")
        q = quality["policies"][policy]["heldout_timing"]
        max_added = max(q[op]["added_pooled_median_ms"] for op in OPS)
        heading("Operational cost")
        para(f"The sum of configured centers is {da + 1} ms. Across the three phases, measured protected medians range from {min(q[op]['rt_ms']['median_ms'] for op in OPS):.3f} to {max(q[op]['rt_ms']['median_ms'] for op in OPS):.3f} ms. The largest increase over a matched Timing OFF median is {max_added:.3f} ms. This describes the typical cost, not the maximum observed delay.")
        heading("Response tails and spread")
        for op in OPS:
            d = summary["delay_policy_diagnostics"][policy][op]
            s = stats[policy, op, "clrt_ms"]
            para(f"<b>{op}:</b> {d['selected_target_miss_count']:,} of {d['heldout_responses']:,} responses exceed the selected target by more than 1 ms ({pct(d['selected_target_miss_fraction'])}). Measured CLRT has SD {s['sd']:.3f} ms and variance {s['variance']:.3f} ms².")
        heading("Attacker result")
        for model in MODEL_NAMES:
            a = result(model, "static_after", policy)
            b = result(model, "adaptive", policy)
            para(f"For {MODEL_NAMES[model]} with 20-response histograms, static balanced accuracy is {pct(a['balanced_accuracy'])}; adaptive balanced accuracy is {pct(b['balanced_accuracy'])}, with a pointwise 95% interval of {interval(b)}. The adaptive model's READ recall is {pct(b['per_class']['READ']['recall'])} and SBO recall is {pct(b['per_class']['SBO']['recall'])}.")
        if da == 5:
            para("This is the lowest-cost setting tested here. It strongly disrupts the original histogram classifier while leaving a small adaptive advantage and more late responses. It is a useful low-overhead reference for further analysis, rather than an established setting that defeats every relevant attacker.")
        elif da == 10:
            para("The extra wait reduces target misses, but the histogram adaptive balanced accuracies are higher than at 5 ms in this sample. Thus spending another 5 ms of configured waiting did not monotonically improve this security measure. The data do not identify a single cause for that change.")
        elif da == 15:
            para("The response distribution is more tightly controlled for the SBO phases, but READ still has a long tail. ACK+CLRT and the histogram give different adaptive scores, so a decision based only on the main histogram plot would omit a tested view of the timing.")
        else:
            para("This setting pays the largest typical delay cost in the comparison. The histogram adaptive advantage is small, but remains positive in these point estimates. The evidence does not justify paying this cost solely on the assumption that eliminating more target misses eliminates all classifiable timing.")

    page("22. What this says about physical operating time",
         "The experiment asks whether an attacker can label an observed signature READ or SBO. SELECT and OPERATE are combined into one SBO class for that main task. They are separated only in the three-phase diagnostic so we can see which response phase contributes a difference.",
         "This is useful evidence that the observable timing pattern of an operation has changed. It does not reconstruct the original CLRT for each packet. It also does not compare predicted physical completion times with an independently measured actuation timestamp.",
         "To answer 'can the attacker recover the native CLRT?', the target should be a native-timing quantity with an appropriate ground truth, rather than only a class label. A regression or distribution-recovery evaluation would then report reconstruction error. Native and protected transactions here are separate executions, so an exact per-transaction native counterfactual is unavailable.",
         "To answer 'can the attacker recover physical operating time?', we would need an independent record of when the physical action began or completed, with the timing endpoints defined. A relay-facing tap or a physical event timestamp would address different missing pieces. The current master-facing captures alone do not supply that ground truth.",
         "The defensible result is therefore about the reliability of these operation classifiers on observed timing. It supports a reduction in a timing clue. It leaves device identification across a device population and direct physical-time recovery as separate questions.")

    page("23. Why can the adaptive attacker still work at all?",
         "The measured outputs establish residual predictive ability, but do not uniquely identify its cause. The following distinctions keep the explanation tied to evidence.")
    table([["Possible clue", "Evidence we have", "What remains to establish"],
           ["Long response tails", "CLRT SD, variance, p99 and target-miss counts differ across operations.", "Whether removing or equalizing that tail removes the predictive advantage."],
           ["ACK timing", "ACK+CLRT and histogram scores differ at the same D_A.", "An ACK-only comparison and matched feature ablation; the current inputs also summarize data differently."],
           ["Weights of timing peaks", "The chosen delays are discrete; measured distributions can have different peak weights or residuals.", "A class-conditioned peak/residual test tied to the same held-out splits."],
           ["SBO mixture", "SBO combines SELECT and OPERATE response intervals.", "How much discrimination comes from either phase, and from the assumed grouping of observations."],
           ["Class frequency", "Two SBO response observations occur for each READ in this task.", "Accuracy alone cannot separate this preference from useful class discrimination."]], [1.3, 2.65, 3.15])
    para("A wider distribution is not automatically harder to learn. If READ has a characteristic long tail and SBO does not, that wide tail can be a fingerprint. Likewise, making the central gap exactly equal for all operations can still leave a classifier a clue in the frequency of exceptional responses.")
    para("Neither FF-ANN nor naive Bayes supplies a causal feature explanation by itself. A correlation between an input and a prediction is useful for diagnosis, but does not demonstrate which packet-processing step created the difference. The next analysis should isolate candidate clues before changing the mechanism.")

    page("24. What to test before changing the mechanism",
         "First, measure the remaining clues under the same held-out protocol. Compare ACK-only, CLRT-only, and combined timing inputs using matched representations where possible. Compare ordinary tails with class-matched tail distributions. Record whether each test improves on the majority-class baseline and whether it still finds READ, not just SBO.",
         "Second, inspect the effect of discrete timing choices. A prospective observer may know the configured set of possible delays without knowing the random draw of each transaction. Testing inference from that public set is different from giving the model the selected per-packet value. Such a test should keep the actual draw as audit information only.",
         "Third, address a confirmed clue with a narrow mechanism change. If native arrival tails are responsible, a longer holding opportunity may help but adds latency. If ACK behavior leaks, changing only the response-gap distribution will not address it. If class-conditioned peak weights leak, use a common class-independent output distribution and check it on observed output, not just in the configuration.",
         "These are proposed experiments and mechanisms, not implemented results. Each would need fresh validation of request/response correctness, release behavior, retransmissions, stage resources, and delay. An output schedule also needs an explicit late-response rule because waiting cannot force a response that does not yet exist.",
         "Finally, choose the smallest-delay setting that meets a declared attacker criterion on new confirmation data. Account for all model families, feature inputs, and observation windows included in that criterion. A pointwise interval for one favorable model is insufficient for a claim covering the whole attacker set. The existing grid can guide the choice; repeatedly selecting on its test results should not turn it into independent confirmation evidence.")

    page("25. The result to explain to Dr. Lin",
         "The original timing data are highly classifiable by the two histogram model families. After obfuscation, the same frozen models perform much worse. That is direct evidence that the old operation-timing pattern transfers poorly.",
         "An attacker that trains only on protected data can recover a smaller signal. The adaptive models often choose SBO, which appears twice as often in the response-signature task. This makes ordinary accuracy around two thirds less impressive than it sounds. Balanced accuracy and per-class recall show the remaining discrimination more clearly.",
         "Increasing D_A reduces some timing-target overruns while increasing the usual response delay. It does not produce a monotonic drop in attacker performance. The 5 ms setting has the smallest measured typical overhead among these four, but the data do not establish that it or any other setting removes every relevant timing clue.",
         "The next useful step is to identify which observable feature sustains the adaptive advantage. That makes a low-cost mechanism change more defensible than increasing D_A simply because it makes the timing distribution look cleaner. Confirm the eventual choice using fresh data and an explicit attacker-success rule.",
         "The strongest supported claim concerns operation-classification performance on this relay workload. The timing plots and scores do not by themselves prove recovery or hiding of physical actuation time, device identity, or exact native per-packet CLRT. Those require different labels or ground truth.")

    page("26. Glossary and reproducibility")
    table([["Term", "Plain-English meaning"],
           ["CLRT", "The measured time between the ACK and application response."],
           ["Feature", "A number, or list of numbers, given to the classifier."],
           ["Signature / pool", "A classifier input built from one or more response observations."],
           ["Bin", "A time interval used to count histogram observations."],
           ["Support", "The number of true examples of a class in the evaluated population."],
           ["Held-out", "Reserved for testing; not used to fit or select model settings."],
           ["Macro average", "Average the class scores with equal weight for each class."],
           ["Confusion matrix", "A count table of true labels versus predicted labels."],
           ["Standard deviation", "Spread around the mean, in the original measurement unit."],
           ["Variance", "Squared spread; here CLRT variance is in square milliseconds."],
           ["Ablation", "Repeat a comparison after removing a feature or component to test its contribution."],
           ["Bootstrap interval", "Uncertainty summary formed by repeatedly resampling the observed rounds."]], [1.5, 5.6])
    para("The report and all its plots are generated locally from the saved evaluation and transaction table. The classifier metrics were refreshed using the saved chosen model settings, with checks that the aggregate confusion matrices and scores match the previous results. This expansion changes explanation and presentation; it does not constitute another hardware acquisition.")

    page("26 continued. Where each number comes from")
    table([["File", "What it contains"],
           ["results.json", "Model settings, aggregate metrics, per-class scores, per-round scores, confusion matrices and source hashes."],
           ["metrics.csv", "One row per classifier/task/input/pool/scenario/setting result."],
           ["round_metrics.csv", "Round accuracy, macro precision, balanced accuracy and class precision/recall."],
           ["per_class_metrics.csv", "Pooled class precision/recall, support and per-class round means/minima."],
           ["tutorial_timing_statistics.csv", "Held-out ACK, CLRT and total-time means, SD, sample variance and quantiles by operation and setting."],
           ["../grid_report.json", "Matched-reference latency differences, target-miss and coverage diagnostics, and full-run capture quality."],
           ["../final/primarytransactions.csv", "The matched packet-timing observations from which the tutorial's timing summaries are computed."],
           ["formby_report.py / formby_tutorial.py", "The figure/export generator and this tutorial's prose and data tables."]], [2.3, 4.8])
    para("Regenerate the PDF and explanatory figures from the repository root with:<br/><font face='Courier' size='8'>python3 defense4/timing/latency_search/formby_report.py</font>")
    para("Source transaction-table SHA-256:<br/><font face='Courier' size='7'>" + source["csv_sha256"] + "</font>")
    para("The reference for the classifier families and Fig. 12 is the local Formby paper, paper/rewrite/corpus/references/device_fingerprinting_2016.pdf. Our operation labels, training/test split, x-axis, and minimum-score aggregation are explicitly defined here; visual similarity does not make the evaluations identical.")
    return story
