import type { WTerm } from '@wterm/vue';

export interface WtermAppearance {
    fontSize?: number | string;
    lineHeight?: number | string;
    letterSpacing?: number | string;
    fontFamily?: string;
    backgroundColor?: string;
    foregroundColor?: string;
}

/**
 * wterm has no font/color options: everything is driven by CSS custom properties on
 * the `.wterm` root element (see @wterm/dom/terminal.css). This maps the panel's
 * terminal settings onto those variables.
 *
 * `--term-row-height` is normally measured by WTerm during init, but only then: WTerm does
 * not re-measure when the font changes at runtime. Because `.term-row` derives both its
 * `height` and its `line-height` from the variable, deriving it here as well keeps the grid
 * consistent while the user edits the font settings.
 */
export function wtermStyleVars(appearance: WtermAppearance): Record<string, string> {
    const vars: Record<string, string> = {};

    const fontSize = Number(appearance.fontSize);
    if (Number.isFinite(fontSize) && fontSize > 0) {
        vars['--term-font-size'] = `${fontSize}px`;
    }

    const lineHeight = Number(appearance.lineHeight);
    if (Number.isFinite(lineHeight) && lineHeight > 0) {
        vars['--term-line-height'] = `${lineHeight}`;
    }

    if (Number.isFinite(fontSize) && fontSize > 0 && Number.isFinite(lineHeight) && lineHeight > 0) {
        vars['--term-row-height'] = `${Math.ceil(fontSize * lineHeight)}px`;
    }

    // wterm renders fixed `1ch`/`2ch` boxes for block elements and wide glyphs, so the
    // letter spacing has to be compensated on those boxes (see the scoped styles).
    const letterSpacing = Number(appearance.letterSpacing);
    vars['--panel-term-letter-spacing'] =
        Number.isFinite(letterSpacing) && letterSpacing > 0 ? `${letterSpacing}px` : '0px';

    if (appearance.fontFamily) {
        vars['--term-font-family'] = appearance.fontFamily;
    }
    if (appearance.backgroundColor) {
        vars['--term-bg'] = appearance.backgroundColor;
    }
    if (appearance.foregroundColor) {
        vars['--term-fg'] = appearance.foregroundColor;
    }
    return vars;
}

/** Methods exposed by the `Terminal` component from `@wterm/vue`. */
export interface WtermTerminalExposed {
    write(data: string | Uint8Array): void;
    resize(cols: number, rows: number): void;
    focus(): void;
    instance: WTerm | null;
}

/**
 * wterm has no `reset()`: RIS (ESC c) is the closest equivalent and clears the
 * screen, the scrollback and the parser state.
 */
export const WTERM_RESET = '\x1bc';

/** wterm drops `\n`; the panel's log streams are line based, so normalise them. */
export function toWtermNewlines(data: string): string {
    return data.replace(/\r?\n/g, '\r\n');
}
