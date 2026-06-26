// Visible split-token de-obfuscation (F3) — matching-copy only (R4). Two complementary,
// backtracking-safe passes that reconstruct keywords an attacker has split with visible
// separators, so the existing L3 keyword regexes (which require contiguous words) can still
// fire. Neither pass touches decodeCopy (would corrupt base64url's `-`/`_`) or modelCopy.
// Underscore is deliberately EXCLUDED from the separator set: special/control tokens
// (`<|im_start|>`, `begin_of_text`, `start_header_id`, ...) are snake_case, and collapsing
// "im_start" -> "imstart" would break the literal-token detector it's there to feed.

// Pass 1 — collapses a single punctuation/newline char directly between two multi-letter
// chunks with no surrounding whitespace: "pre.vious" / "pre-vious" / "pre\nvious" -> "previous".
// Sentence punctuation followed by whitespace ("cat. Dog") never matches since the char
// immediately after the separator must be a letter, not a space.
//
// The continuation (second chunk) is restricted to LOWERCASE. This runs BEFORE casefolding, so
// case is still meaningful here, and the restriction is what separates a real sentence boundary
// with a missing space ("instructions.Tell", "Avoidance.Ignore" — capitalized next word) from a
// genuine intra-word split ("pre.vious" — lowercase). Without it we FUSE two complete words and
// destroy the `\b` boundaries the L3 keyword regexes rely on, turning caught attacks into misses
// (observed on real-corpus samples gandalf-00810 / dan-01065). An attacker capitalizing the
// split-half ("pre.Vious") is unusual and draws the eye, so the trade strongly favors this guard.
const INTRA_WORD_SPLIT_RE = /([A-Za-z]{2,})[.\-‐-―\n]([a-z]{2,})/g;
const INTRA_WORD_SPLIT_PRECHECK = /[.\-‐-―\n]/;

export function collapseIntraWordSplit(s: string): string {
  if (!INTRA_WORD_SPLIT_PRECHECK.test(s)) return s;
  let out = s;
  // A single replace() pass only resolves non-overlapping matches left-to-right; a chain like
  // "a.b.c.d" needs a couple of passes to fully join. Capped so pathological input can't loop.
  for (let pass = 0; pass < 3; pass++) {
    const next = out.replace(INTRA_WORD_SPLIT_RE, '$1$2');
    if (next === out) break;
    out = next;
  }
  return out;
}

// Pass 2 — collapses a run of >=3 isolated single-letter tokens each separated by exactly one
// space/period/hyphen: "i g n o r e" / "i.g.n.o.r.e" -> "ignore". Genuine 2-letter abbreviations
// ("e.g.", "U.S.") fall under the >=3 threshold and are left alone. A run breaks naturally on a
// double separator (two spaces, or a sentence "X. Y") because the char immediately after the
// single separator must itself be an isolated letter, not a real word.
function isAsciiLetter(code: number): boolean {
  return (code >= 97 && code <= 122) || (code >= 65 && code <= 90);
}
function isSpacingSep(code: number): boolean {
  return (
    code === 32 || // space
    code === 9 || // tab
    code === 10 || // \n
    code === 13 || // \r
    code === 46 || // .
    code === 45 // -
  );
}

export function collapseLetterSpacing(s: string): string {
  const n = s.length;
  // Lazy output: scan cheaply (no allocation) until the FIRST collapsible run is found, then
  // start `out` from the untouched prefix. Benign prose (no ≥3 isolated-letter runs) returns the
  // original string with zero allocation — keeping this off the few-KB hot-path cost.
  let out = '';
  let outStarted = false;
  let i = 0;
  let copiedUpto = 0; // index in `s` up to which `out` already mirrors the input
  while (i < n) {
    const c = s.charCodeAt(i);
    const isIsolatedLetter =
      isAsciiLetter(c) &&
      (i === 0 || !isAsciiLetter(s.charCodeAt(i - 1))) &&
      (i + 1 >= n || !isAsciiLetter(s.charCodeAt(i + 1)));
    if (isIsolatedLetter) {
      let j = i + 1;
      let letters = s[i] as string;
      let tokens = 1;
      while (
        j < n &&
        isSpacingSep(s.charCodeAt(j)) &&
        j + 1 < n &&
        isAsciiLetter(s.charCodeAt(j + 1)) &&
        (j + 2 >= n || !isAsciiLetter(s.charCodeAt(j + 2)))
      ) {
        letters += s[j + 1];
        tokens++;
        j += 2;
      }
      if (tokens >= 3) {
        if (!outStarted) {
          out = s.slice(0, i);
          outStarted = true;
        } else {
          out += s.slice(copiedUpto, i);
        }
        out += letters;
        copiedUpto = j;
        i = j;
        continue;
      }
    }
    i++;
  }
  if (!outStarted) return s;
  if (copiedUpto < n) out += s.slice(copiedUpto, n);
  return out;
}
