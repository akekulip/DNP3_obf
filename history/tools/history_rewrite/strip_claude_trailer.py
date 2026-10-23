# Message callback for the history rewrite: removes the Claude co-author trailers from commit
# messages. Nothing else about any commit changes. Same tree, same author, same committer, same
# dates; only the message text loses the trailer lines.
#
# Used as the --message-callback body. See README.md in this directory for the two commands.
import re

msg = message.decode("utf-8", "replace")                       # noqa: F821  (injected name)
msg = re.sub(r"[ \t]*Co-[Aa]uthored-[Bb]y:[^\n]*[Cc]laude[^\n]*\n?", "", msg)
msg = re.sub(r"[ \t]*Claude-Session:[^\n]*\n?", "", msg)
msg = re.sub(r"[ \t]*\U0001F916[^\n]*Generated with[^\n]*\n?", "", msg)
msg = re.sub(r"[ \t]*Generated with \[Claude Code\][^\n]*\n?", "", msg)
msg = re.sub(r"\n{3,}", "\n\n", msg).rstrip() + "\n"
return msg.encode("utf-8")                                     # noqa: F706  (callback body)
