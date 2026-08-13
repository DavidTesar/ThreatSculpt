// Applies the stored theme before first paint, so a dark-mode user never sees a white
// flash on load. Loaded as a render-blocking <script> in <head> rather than inlined:
// inline script would force `script-src 'unsafe-inline'` into the CSP, and this one
// tiny convenience is not worth giving up script-src for.
//
// Deliberately dependency-free and untranspiled — it runs before the bundle exists.
(function () {
  try {
    var stored = localStorage.getItem('ts.theme');
    var theme =
      stored === 'light' || stored === 'dark'
        ? stored
        : window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light';
    document.documentElement.setAttribute('data-theme', theme);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
