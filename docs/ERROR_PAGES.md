# Mr Patchy HTTP pages

Browser navigation requests that explicitly accept HTML receive branded pages for
HTTP 403, 404, redirects and server failures. The status code is preserved. The
pages work without JavaScript or a database and use the existing dark workbench
theme with original illustrations derived from the canonical Mr Patchy mascot.

| Response | Artwork |
| --- | --- |
| 300–399, except bodyless 304 | Direction signs |
| 403 | Locked gate |
| 404 | Searching a map with a magnifying glass |
| 500 and other server failures | Frazzled mechanic |
| 501 | Missing tool |
| 502 | Disconnected network cable |
| 503 | Server repair and maintenance cone |
| 504 | Waiting beside a clock |

Redirects keep their Location header and normal automatic behavior. A browser
that follows the redirect will show its destination, not the fallback page.
The fallback only offers a destination link for a safe local path; external
sign-in redirects retain their original header without adding an external link.
304 remains bodyless. Cookies, authentication headers and Retry-After survive
HTML replacement. Public pages never echo exception details or requested URLs.

API, health-check and enrollment URLs, non-HTML requests, non-document fetches,
non-GET/HEAD operations and attachment downloads retain their original response
contracts. Small inline form feedback and success messages remain lightweight;
failed application views and panels use the shared error illustration.

The app decorates responses it handles. An external proxy's own failure while the
app is unreachable must be configured by that proxy's administrator; it cannot
execute the application middleware. Static examples are available under
`app/static/errors/` for use by such a handler, along with `app/static/error.css`
and `app/static/mascot/`. Do not serve an error document with a successful status.

The static examples are generated from the same live renderer:

```sh
python -c "from app.error_pages import write_previews; write_previews()"
```

Validation: `python -m pytest tests/test_error_pages.py -q` and
`node tests/ui_error_mascot.cjs`. The latter is included in `npm run test:ui` and
checks sign-in errors, retry behavior, escaping and all page illustrations at
320, 768 and 1440 pixels. Set `SCREENSHOT_DIR` to capture previews.

Artwork was generated with the built-in imagegen tool using the existing
`mr-patchy-welcome.png` as the character/style reference. The initial frazzled
pose also used the maintainer-supplied reference. Transparent WebP deliverables
are resized for browser delivery; the canonical welcome/working assets remain
unchanged. Art direction: retain the raccoon's gray/cream fur, amber eyes, black
mask, striped tail and patched denim overalls; show one clear action or prop for
each response class, with no text embedded in the artwork.
