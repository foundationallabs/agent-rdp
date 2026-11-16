//! Whether Win+R opened the Run dialog, judged from the remote screen.
//!
//! Nothing in RDP says the shell is ready for Win+R. Until it is (17–44 s after a first logon),
//! the hotkey does nothing and typed text goes to whatever has focus: on the desktop, type-ahead
//! selects an icon and Enter opens it. So the launch command is typed only after the screen
//! shows a Run dialog, and Enter is pressed only after the typed text shows in it.
//!
//! The dialog shows as a change of the bottom-left area, where Windows opens it, while the
//! area far from it stays as it was. The screen is sampled twice before Win+R: if the
//! bottom-left area was already changing, nothing is taken for the dialog; motion already under
//! way far from it (a video, a scrolling console) is not held against the dialog. These are
//! pixel heuristics, not a view of the window tree: a change in the same place that is not the
//! Run dialog can pass the first check, which is why the typed text must show too.

/// A part of the screen, as fractions of its width and height.
struct Area {
    left: f32,
    top: f32,
    right: f32,
    bottom: f32,
}

/// Where the Run dialog opens: bottom-left, above the taskbar. The bottom edge leaves 6% of the
/// height for the 40-pixel taskbar at 100% scaling, which fits from 667 rows up; on smaller
/// screens the area takes in a few rows of the taskbar.
const DIALOG_AREA: Area = Area {
    left: 0.0,
    top: 0.4,
    right: 0.3,
    bottom: 0.94,
};

/// Far from the dialog, and from the notifications that open bottom-right: the top-right
/// quarter.
const ELSEWHERE_AREA: Area = Area {
    left: 0.5,
    top: 0.0,
    right: 1.0,
    bottom: 0.5,
};

/// The dialog covers well over this share of [`DIALOG_AREA`]: about half at 1280x800, a few
/// percent at 3840x2160 and 100% scaling.
const DIALOG_MIN_CHANGE: f32 = 0.02;

/// A change of this share of [`ELSEWHERE_AREA`] means the whole screen is changing.
const ELSEWHERE_MAX_CHANGE: f32 = 0.10;

/// Typing the launch command into the dialog changes well over this many pixels of
/// [`DIALOG_AREA`] (the visible tail of the command, an autocomplete list); a blinking caret
/// changes a few dozen.
const TYPED_MIN_PIXELS: usize = 100;

const BYTES_PER_PIXEL: usize = 4;

/// The pixels of the screen areas that show the Run dialog.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScreenSample {
    dialog: Vec<u8>,
    elsewhere: Vec<u8>,
}

impl ScreenSample {
    /// Sample a tightly packed 32-bit frame of `width` x `height` pixels.
    pub(crate) fn of(width: usize, height: usize, frame: &[u8]) -> Self {
        Self {
            dialog: crop(width, height, frame, &DIALOG_AREA),
            elsewhere: crop(width, height, frame, &ELSEWHERE_AREA),
        }
    }

    /// Whether text typed between `self` and `after` shows in the Run dialog's area.
    pub(crate) fn shows_typing(&self, after: &Self) -> bool {
        changed_pixels(&self.dialog, &after.dialog).is_some_and(|n| n >= TYPED_MIN_PIXELS)
    }
}

/// The screen before Win+R, sampled twice to tell motion already under way from the dialog.
#[derive(Debug)]
pub(crate) struct ScreenBefore {
    sample: ScreenSample,
    dialog_moving: bool,
    elsewhere_moving: bool,
}

impl ScreenBefore {
    /// From two samples taken shortly apart, `first` then `second`.
    pub(crate) fn new(first: &ScreenSample, second: ScreenSample) -> Self {
        Self {
            dialog_moving: changed_share(&first.dialog, &second.dialog) >= DIALOG_MIN_CHANGE,
            elsewhere_moving: changed_share(&first.elsewhere, &second.elsewhere)
                >= ELSEWHERE_MAX_CHANGE,
            sample: second,
        }
    }

    /// Whether the screen went from this to `after` by opening the Run dialog.
    pub(crate) fn run_dialog_opened(&self, after: &ScreenSample) -> bool {
        !self.dialog_moving
            && changed_share(&self.sample.dialog, &after.dialog) >= DIALOG_MIN_CHANGE
            && (self.elsewhere_moving
                || changed_share(&self.sample.elsewhere, &after.elsewhere) < ELSEWHERE_MAX_CHANGE)
    }
}

fn crop(width: usize, height: usize, frame: &[u8], area: &Area) -> Vec<u8> {
    if frame.len() < width * height * BYTES_PER_PIXEL {
        return Vec::new();
    }
    let scale = |fraction: f32, size: usize| (fraction * size as f32) as usize;
    let (left, right) = (scale(area.left, width), scale(area.right, width));
    let row_bytes = width * BYTES_PER_PIXEL;
    let mut out = Vec::with_capacity((right - left) * BYTES_PER_PIXEL * height);
    for row in scale(area.top, height)..scale(area.bottom, height) {
        let start = row * row_bytes;
        out.extend_from_slice(
            &frame[start + left * BYTES_PER_PIXEL..start + right * BYTES_PER_PIXEL],
        );
    }
    out
}

/// How many pixels differ; `None` when the samples don't line up (the screen was resized) or
/// are empty.
fn changed_pixels(before: &[u8], after: &[u8]) -> Option<usize> {
    if before.len() != after.len() || before.is_empty() {
        return None;
    }
    let differing = before
        .chunks_exact(BYTES_PER_PIXEL)
        .zip(after.chunks_exact(BYTES_PER_PIXEL))
        .filter(|(a, b)| a != b)
        .count();
    Some(differing)
}

/// The share of pixels that differ; all of them when the samples don't line up or are empty.
fn changed_share(before: &[u8], after: &[u8]) -> f32 {
    changed_pixels(before, after)
        .map_or(1.0, |n| n as f32 / (before.len() / BYTES_PER_PIXEL) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH: usize = 1280;
    const HEIGHT: usize = 800;

    /// A frame of one colour.
    fn frame(colour: u8) -> Vec<u8> {
        vec![colour; WIDTH * HEIGHT * BYTES_PER_PIXEL]
    }

    /// Paint the rectangle `x..x+w`, `y..y+h` in `colour`.
    fn paint(frame: &mut [u8], (x, y, w, h): (usize, usize, usize, usize), colour: u8) {
        for row in y..y + h {
            let start = (row * WIDTH + x) * BYTES_PER_PIXEL;
            frame[start..start + w * BYTES_PER_PIXEL].fill(colour);
        }
    }

    fn sample(frame: &[u8]) -> ScreenSample {
        ScreenSample::of(WIDTH, HEIGHT, frame)
    }

    /// Before Win+R, the screen as `frame` both times.
    fn still(frame: &[u8]) -> ScreenBefore {
        ScreenBefore::new(&sample(frame), sample(frame))
    }

    /// Where Windows Server 2022 opens the Run dialog at 1280x800 and 100% scaling.
    const RUN_DIALOG: (usize, usize, usize, usize) = (12, 540, 400, 210);

    /// The command's tail in the dialog's edit box.
    const TYPED_TEXT: (usize, usize, usize, usize) = (80, 640, 260, 8);

    /// A video playing top-right.
    const VIDEO: (usize, usize, usize, usize) = (700, 0, 580, 380);

    fn opened(before: &[u8], after: &[u8]) -> bool {
        still(before).run_dialog_opened(&sample(after))
    }

    fn with_dialog(mut frame: Vec<u8>) -> Vec<u8> {
        paint(&mut frame, RUN_DIALOG, 200);
        frame
    }

    #[test]
    fn a_dialog_opening_bottom_left_is_the_run_dialog() {
        let desktop = frame(10);
        assert!(opened(&desktop, &with_dialog(desktop.clone())));
    }

    #[test]
    fn an_unchanged_screen_is_no_dialog() {
        assert!(!opened(&frame(10), &frame(10)));
    }

    #[test]
    fn a_change_across_the_screen_is_no_dialog() {
        // The desktop painting in, or a large window opening, while Win+R is not live yet.
        assert!(!opened(&frame(10), &with_dialog(frame(90))));
    }

    #[test]
    fn a_small_change_bottom_left_is_no_dialog() {
        // A desktop icon redrawn, a caret blinking.
        let desktop = frame(10);
        let mut icon = desktop.clone();
        paint(&mut icon, (20, 600, 48, 48), 200);
        assert!(!opened(&desktop, &icon));
    }

    #[test]
    fn small_changes_elsewhere_do_not_hide_the_dialog() {
        // The clock or a spinner updating while the dialog opens.
        let desktop = frame(10);
        let mut after = with_dialog(desktop.clone());
        paint(&mut after, (1100, 100, 64, 64), 77);
        assert!(opened(&desktop, &after));
    }

    #[test]
    fn motion_elsewhere_before_win_r_does_not_hide_the_dialog() {
        let mut first = frame(10);
        paint(&mut first, VIDEO, 1);
        let mut second = frame(10);
        paint(&mut second, VIDEO, 2);
        let mut after = with_dialog(frame(10));
        paint(&mut after, VIDEO, 3);
        let before = ScreenBefore::new(&sample(&first), sample(&second));
        assert!(before.run_dialog_opened(&sample(&after)));
        // Unless the motion is new.
        assert!(!still(&second).run_dialog_opened(&sample(&after)));
    }

    #[test]
    fn nothing_is_taken_for_the_dialog_while_its_area_is_changing() {
        // The desktop painting in across the dialog's area before Win+R.
        let first = frame(10);
        let mut second = frame(10);
        paint(&mut second, (0, 400, 384, 200), 50);
        let before = ScreenBefore::new(&sample(&first), sample(&second));
        assert!(!before.run_dialog_opened(&sample(&with_dialog(second))));
    }

    #[test]
    fn typing_into_the_dialog_shows() {
        let dialog = with_dialog(frame(10));
        let mut typed = dialog.clone();
        paint(&mut typed, TYPED_TEXT, 0);
        assert!(sample(&dialog).shows_typing(&sample(&typed)));
    }

    #[test]
    fn typing_onto_an_unchanged_desktop_does_not_show() {
        // The dialog closed (or never was one), so the text went to the desktop.
        assert!(!sample(&frame(10)).shows_typing(&sample(&frame(10))));
        // A caret blinking is not typing.
        let dialog = with_dialog(frame(10));
        let mut caret = dialog.clone();
        paint(&mut caret, (80, 640, 1, 16), 0);
        assert!(!sample(&dialog).shows_typing(&sample(&caret)));
    }

    #[test]
    fn a_resized_or_empty_screen_is_no_dialog() {
        let smaller = ScreenSample::of(640, 400, &vec![10; 640 * 400 * BYTES_PER_PIXEL]);
        let after = sample(&with_dialog(frame(10)));
        assert!(!ScreenBefore::new(&smaller, smaller.clone()).run_dialog_opened(&after));
        assert!(!smaller.shows_typing(&after));
        // A frame shorter than its size says (none decoded yet) samples as empty.
        let empty = ScreenSample::of(WIDTH, HEIGHT, &[]);
        assert_eq!(empty, ScreenSample::default());
        assert!(!ScreenBefore::new(&empty, empty.clone()).run_dialog_opened(&empty));
        assert!(!empty.shows_typing(&empty));
    }

    #[test]
    fn the_dialog_shows_at_large_resolutions_too() {
        // 3840x2160 at 100% scaling: the dialog covers the least of the area here.
        let (w, h) = (3840, 2160);
        let desktop = vec![10; w * h * BYTES_PER_PIXEL];
        let mut with_dialog = desktop.clone();
        for row in 2160 - 48 - 210..2160 - 48 {
            let start = (row * w + 12) * BYTES_PER_PIXEL;
            with_dialog[start..start + 400 * BYTES_PER_PIXEL].fill(200);
        }
        let before = ScreenSample::of(w, h, &desktop);
        let after = ScreenSample::of(w, h, &with_dialog);
        assert!(ScreenBefore::new(&before, before.clone()).run_dialog_opened(&after));
    }
}
