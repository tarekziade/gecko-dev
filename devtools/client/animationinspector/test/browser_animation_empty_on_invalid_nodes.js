/* vim: set ts=2 et sw=2 tw=80: */
/* Any copyright is dedicated to the Public Domain.
 http://creativecommons.org/publicdomain/zero/1.0/ */
"use strict";

requestLongerTimeout(2);

// Test that the panel shows no animation data for invalid or not animated nodes

const STRINGS_URI = "chrome://devtools/locale/animationinspector.properties";
const L10N = new ViewHelpers.L10N(STRINGS_URI);

add_task(function*() {
  yield addTab(TEST_URL_ROOT + "doc_simple_animation.html");
  let {inspector, panel, window} = yield openAnimationInspector();
  let {document} = window;

  info("Select node .still and check that the panel is empty");
  let stillNode = yield getNodeFront(".still", inspector);
  let onUpdated = panel.once(panel.UI_UPDATED_EVENT);
  yield selectNode(stillNode, inspector);
  yield onUpdated;

  is(panel.animationsTimelineComponent.animations.length, 0,
     "No animation players stored in the timeline component for a still node");
  is(panel.animationsTimelineComponent.animationsEl.childNodes.length, 0,
     "No animation displayed in the timeline component for a still node");
  is(document.querySelector("#error-type").textContent,
     L10N.getStr("panel.invalidElementSelected"),
     "The correct error message is displayed");

  info("Select the comment text node and check that the panel is empty");
  let commentNode = yield inspector.walker.previousSibling(stillNode);
  onUpdated = panel.once(panel.UI_UPDATED_EVENT);
  yield selectNode(commentNode, inspector);
  yield onUpdated;

  is(panel.animationsTimelineComponent.animations.length, 0,
     "No animation players stored in the timeline component for a text node");
  is(panel.animationsTimelineComponent.animationsEl.childNodes.length, 0,
     "No animation displayed in the timeline component for a text node");
  is(document.querySelector("#error-type").textContent,
     L10N.getStr("panel.invalidElementSelected"),
     "The correct error message is displayed");

  info("Select the pseudo element node and check that the panel is empty " +
       "and contains the special animated pseudo-element message");
  let pseudoElParent = yield getNodeFront(".pseudo", inspector);
  let {nodes} = yield inspector.walker.children(pseudoElParent);
  let pseudoEl = nodes[0];
  onUpdated = panel.once(panel.UI_UPDATED_EVENT);
  yield selectNode(pseudoEl, inspector);
  yield onUpdated;

  is(panel.animationsTimelineComponent.animations.length, 0,
     "No animation players stored in the timeline component for a pseudo-node");
  is(panel.animationsTimelineComponent.animationsEl.childNodes.length, 0,
     "No animation displayed in the timeline component for a pseudo-node");
  is(document.querySelector("#error-type").textContent,
     L10N.getStr("panel.pseudoElementSelected"),
     "The correct error message is displayed");
});
