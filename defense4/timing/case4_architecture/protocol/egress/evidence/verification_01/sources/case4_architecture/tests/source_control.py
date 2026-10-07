"""Supporting control fragments only; does not execute target packet pipelines."""
import re
from source_eval import Source as FragmentSource


def branch_end(text, start):
    opening=text.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    after=end
    while after<len(text) and text[after].isspace():after+=1
    if text.startswith('else if',after):return branch_end(text,after+5)
    if text.startswith('else',after):
        opening=text.index('{',after);depth=1;end=opening+1
        while depth:
            depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return end


def explicit_else_blocks(text):
    # The frozen fragment helper otherwise consumes statements following an
    # else-if as part of that alternate branch. Preserve the actual suffix.
    while True:
        match=re.search(r'\belse if\b',text)
        if not match:return text
        start=match.start()+5;end=branch_end(text,start)
        text=text[:match.start()]+'else{'+text[start:end]+'}'+text[end:]


class Source(FragmentSource):
    def run(self,text):
        return super().run(explicit_else_blocks(text))
