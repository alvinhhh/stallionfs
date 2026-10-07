const assert = require('node:assert/strict');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
assert.equal(renderToStaticMarkup(React.createElement('div', null, 'ready')), '<div>ready</div>');
assert.equal(require('zod').z.string().parse('ready'), 'ready');
assert.deepEqual(require('lodash').uniq([1, 1, 2]), [1, 2]);
