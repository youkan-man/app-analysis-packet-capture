/* Supplemental diagnostics for pane-resize regression failures. */
const {chromium} = require('playwright');
const fs = require('node:fs');
(async()=>{
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:900}});
 await page.goto('http://127.0.0.1:18080/',{waitUntil:'networkidle'});
 await page.evaluate(()=>{
  window.resizeEvents=[];
  ['pointerdown','pointermove','pointerup','gotpointercapture','lostpointercapture'].forEach(t=>{
   document.addEventListener(t,e=>window.resizeEvents.push({type:t,target:e.target.id,y:e.clientY,button:e.button,share:document.documentElement.style.getPropertyValue('--packet-share')}),true);
  });
 });
 const box=await page.locator('#split-packets').boundingBox();
 const point={x:box.x+box.width/2,y:box.y+box.height/2};
 const inspect=()=>page.evaluate(point=>({
  point,hit:document.elementFromPoint(point.x,point.y)?.outerHTML,
  splitter:document.querySelector('#split-packets').getBoundingClientRect().toJSON(),
  viewer:document.querySelector('.viewer').getBoundingClientRect().toJSON(),
  grid:getComputedStyle(document.querySelector('.viewer')).gridTemplateRows,
  share:document.documentElement.style.getPropertyValue('--packet-share'),
  section:document.querySelector('.packet-section').clientHeight,
  store:localStorage.getItem('packetcap.layout.v3'),events:window.resizeEvents,
 }),point);
 const before=await inspect();
 await page.mouse.move(point.x,point.y);await page.mouse.down();await page.mouse.move(point.x,point.y-130,{steps:8});await page.mouse.up();
 const after=await inspect();
 fs.writeFileSync('artifacts/layout-probe.json',JSON.stringify({before,after},null,2));
 await page.screenshot({path:'artifacts/layout-probe.png'});
 await browser.close();
})().catch(error=>{console.error(error);process.exit(1);});
