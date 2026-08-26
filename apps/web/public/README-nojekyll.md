# Why `.nojekyll` is in this directory

GitHub Pages runs Jekyll over whatever it is given unless told not to, and **Jekyll silently ignores
every path beginning with an underscore**. Next puts the entire client bundle in `_next/`, so a Pages
deploy without this file serves the HTML correctly and returns 404 for all of its JavaScript and CSS —
a blank page with no error anywhere except the network tab.

An empty `.nojekyll` at the root of the published directory disables Jekyll entirely, which is what a
pre-built static export wants: there is nothing here for it to process.

It lives in `public/` rather than being written by a build step because everything in `public/` is
copied verbatim into `out/`, so it cannot be forgotten by a workflow that changes. Next does **not**
add it for `output: "export"` — this was checked rather than assumed.

The desktop build copies it too, where it is inert. Excluding it would mean diverging the two builds
for no gain, and the whole architecture rests on them being the same directory.
