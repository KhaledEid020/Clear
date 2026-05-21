const fs = require('fs');
const code = fs.readFileSync('public/app.js', 'utf8');

// Mock DOM
const domElements = {};
const document = {
  getElementById: (id) => {
    if (!domElements[id]) domElements[id] = {
      classList: { add: ()=>{}, remove: ()=>{}, toggle: ()=>{} },
      innerHTML: '',
      querySelectorAll: () => [],
      style: {},
      dataset: {},
      addEventListener: () => {}
    };
    return domElements[id];
  },
  querySelector: () => {
    return {
      classList: { add: ()=>{}, remove: ()=>{}, toggle: ()=>{} },
      innerHTML: '',
      querySelectorAll: () => [],
      style: {},
      dataset: {},
      addEventListener: () => {}
    };
  },
  querySelectorAll: () => []
};

const window = { location: { pathname: '/run/123' }, addEventListener: ()=>{} };

// Evaluate the script in this context
eval(code);

// Mock data
streamState = {
  steps: new Map([
    ['research_threat_hunting', { status: 'running', title: 'Threat Hunting Evidence', name: 'research_threat_hunting', kind: 'tool_call' }]
  ])
};

const activity = buildActivityFromStreamState();
console.log("Activity from stream:", activity);

try {
  renderActivity('run1', activity, null);
  console.log("Rendered successfully");
} catch (e) {
  console.error("Crash during renderActivity:", e);
}
