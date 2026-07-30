/**
 * A seekable timeline for the illustrated scenes on this site.
 *
 * A scene is a list of cues on a clock rather than a sequential script, which
 * is what makes any point in it reachable. Seeking resets the scene and replays
 * every cue up to the target with transitions suppressed, then playback carries
 * on from there.
 *
 * That only works if two rules hold, and neither is checked for you:
 *
 *   1. Every cue sets state outright. A cue that toggles or increments gives a
 *      different result on the second replay, so scrubbing back and forth would
 *      drift.
 *   2. `reset` clears everything any cue can set. Whatever it misses survives a
 *      seek and leaks into a frame it does not belong in.
 *
 * The clock also drives a `--rate` custom property on the stage, so CSS
 * transitions written as `calc(400ms / var(--rate, 1))` stretch along with the
 * cues instead of staying snappy while the pacing slows down.
 */

export type Cue = { t: number; fn: () => void };

export type SceneOptions = {
  /** Carries `data-paused`, which the transport button styles itself from. */
  root: HTMLElement;
  /** Reset between seeks. Gets `.is-seeking` while a jump is applied. */
  stage: HTMLElement;
  /** Cues in ascending time order. */
  cues: Cue[];
  durationMs: number;
  /** Put the scene back to time zero. See rule 2 above. */
  reset: () => void;
  toggle?: HTMLButtonElement | null;
  seek?: HTMLInputElement | null;
  /** Cycles through `rates` on each click, and shows the current one. */
  rate?: HTMLButtonElement | null;
  /** Playback rates to cycle, starting at the first. */
  rates?: number[];
  /** Fraction of the stage on screen before it starts playing by itself. */
  autoplayAt?: number;
};

export type Scene = {
  time(): number;
  seekTo(ms: number): void;
  setPlaying(on: boolean): void;
};

export function createScene(options: SceneOptions): Scene {
  const { root, stage, cues, durationMs, reset } = options;
  const rates = options.rates?.length ? options.rates : [1, 0.75, 0.5, 0.25];
  const seekMax = Number(options.seek?.max) || 1000;

  let t = 0;
  let cursor = 0;
  let playing = false;
  let last = 0;
  let rateIndex = 0;

  const advance = () => {
    while (cursor < cues.length && cues[cursor]!.t <= t) cues[cursor++]!.fn();
  };

  const paint = () => {
    if (options.seek) options.seek.value = String(Math.round((t / durationMs) * seekMax));
  };

  function seekTo(target: number) {
    t = Math.max(0, Math.min(durationMs, target));
    stage.classList.add("is-seeking");
    reset();
    cursor = 0;
    advance();
    // Commit the suppressed styles before transitions come back on.
    void stage.offsetWidth;
    stage.classList.remove("is-seeking");
    paint();
  }

  function setPlaying(on: boolean) {
    playing = on;
    last = 0;
    root.dataset.paused = String(!on);
    options.toggle?.setAttribute("aria-label", on ? "Pause" : "Play");
  }

  function setRate(index: number) {
    rateIndex = index % rates.length;
    const rate = rates[rateIndex]!;
    stage.style.setProperty("--rate", String(rate));
    if (options.rate) {
      options.rate.textContent = `${rate}x`;
      options.rate.setAttribute("aria-label", `Playback speed ${rate}x, click to change`);
    }
  }

  function frame(now: number) {
    if (playing) {
      // Clamp the step so a backgrounded tab does not skip the whole scene.
      t += last ? Math.min(now - last, 120) * rates[rateIndex]! : 0;
      if (t >= durationMs) {
        seekTo(0);
      } else {
        advance();
        paint();
      }
    }
    last = now;
    requestAnimationFrame(frame);
  }

  options.toggle?.addEventListener("click", () => setPlaying(!playing));
  options.seek?.addEventListener("input", () => {
    seekTo((Number(options.seek!.value) / seekMax) * durationMs);
  });
  options.rate?.addEventListener("click", () => setRate(rateIndex + 1));

  setRate(0);
  seekTo(0);
  setPlaying(false);
  requestAnimationFrame(frame);

  // Hold at the first frame until the scene is actually worth watching.
  const observer = new IntersectionObserver(
    (entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        observer.disconnect();
        setPlaying(true);
      }
    },
    { threshold: options.autoplayAt ?? 0.3 },
  );
  observer.observe(stage);

  return { time: () => t, seekTo, setPlaying };
}
