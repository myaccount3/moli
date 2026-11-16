document.head.innerHTML = `<style>
html,body { margin:0; background:white }
#editor { width:80px; white-space:pre; font:24px/32px monospace; caret-color:red; outline:none }
#atomic { display:inline-block; width:24px; height:24px; background:lime }
::selection { background:rgb(180,213,255); color:black }
</style>`;
document.body.innerHTML = '<div id="editor" contenteditable></div>';
window.setAtomicCaret = (text, offset, styles = '') => {
  const editor = document.getElementById('editor');
  editor.style.cssText = styles;
  editor.innerHTML = '<span id="atomic" contenteditable="false"></span>';
  editor.append(document.createTextNode(text));
  editor.blur();
  editor.focus();
  getSelection().collapse(editor.lastChild, offset);
};
window.setAtomicRange = (text, start, end, styles = '', overlap = '') => {
  setAtomicCaret(text, 0, styles);
  const editor = document.getElementById('editor');
  if (overlap === 'earlier') {
    document.getElementById('atomic').style.marginRight = '-8px';
  }
  getSelection().setBaseAndExtent(editor.lastChild, start, editor.lastChild, end);
  if (overlap === 'later') {
    const cover = document.createElement('span');
    cover.contentEditable = 'false';
    // Overlay the glyphless break highlight entirely. The selection rect
    // spans roughly y=0..34 (line height plus the break's extra extent), so
    // the cover must reach above y=0 as well as below y=34. A taller box
    // pulled further up avoids leaving a thin strip of highlight visible at
    // the top, which made this compositing assertion depend on font metrics.
    cover.style.cssText = 'display:inline-block;vertical-align:top;width:40px;height:48px;margin-top:-40px;background:red';
    editor.append(cover);
  }
};
setAtomicCaret('\n', 0);
'installed';
