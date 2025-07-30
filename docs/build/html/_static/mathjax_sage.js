MathJax.Hub.Config({
  imageFont: null,
  tex2jax: {
    inlineMath: [['$','$'],['\\(','\\)']],
    processEscapes: true,
  },
  styles: {
    ".MathJax .mo, .MathJax .mi": {
      color: "inherit ! important"
    }
  },
  TeX: {
    MAXBUFFER: 50*1024,

    Macros: {
     
    }
  }
});

// This path is a little funny because we have to load our local
// config file as '../mathjax_sage' in the theme conf.py
MathJax.Ajax.loadComplete("[MathJax]/config/../mathjax_sage.js")