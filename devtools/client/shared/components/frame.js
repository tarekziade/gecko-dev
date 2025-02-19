/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { DOM: dom, createClass, PropTypes } = require("devtools/client/shared/vendor/react");
const { getSourceNames, parseURL } = require("devtools/client/shared/source-utils");
const { L10N } = require("resource://devtools/client/shared/widgets/ViewHelpers.jsm").ViewHelpers;
const l10n = new L10N("chrome://devtools/locale/components.properties");

module.exports = createClass({
  propTypes: {
    // SavedFrame, or an object containing all the required properties.
    frame: PropTypes.shape({
      functionDisplayName: PropTypes.string,
      source: PropTypes.string.isRequired,
      line: PropTypes.number,
      column: PropTypes.number,
    }).isRequired,
    // Clicking on the frame link -- probably should link to the debugger.
    onClick: PropTypes.func.isRequired,
    // Option to display a function name before the source link.
    showFunctionName: PropTypes.bool,
    // Option to display a host name after the source link.
    showHost: PropTypes.bool,
  },

  getDefaultProps() {
    return {
      showFunctionName: false,
      showHost: false,
    };
  },

  displayName: "Frame",

  render() {
    let { onClick, frame, showFunctionName, showHost } = this.props;
    const { short, long, host } = getSourceNames(frame.source);
    // Reparse the URL to determine if we should link this; `getSourceNames`
    // has already cached this indirectly. We don't want to attempt to
    // link to "self-hosted" and "(unknown)".
    const isLinkable = !!parseURL(frame.source);
    const elements = [];

    let tooltip = long;
    // Exclude all falsy values, including `0`, as even
    // a number 0 for line doesn't make sense, and should not be displayed.
    // If source isn't linkable, don't attempt to append line and column
    // info, as this probably doesn't make sense.
    if (isLinkable && frame.line) {
      tooltip += `:${frame.line}`;
      // Intentionally exclude 0
      if (frame.column) {
        tooltip += `:${frame.column}`;
      }
    }

    let onClickTooltipString = l10n.getFormatStr("frame.viewsourceindebugger", tooltip);
    let attributes = {
      "data-url": long,
      className: "frame-link",
      title: tooltip,
    };

    if (isLinkable) {
      elements.push(dom.a({
        className: "frame-link-filename",
        onClick,
        title: onClickTooltipString
      }, short));
    } else {
      // If source is not a URL (self-hosted, eval, etc.), don't make
      // it an anchor link, as we can't link to it.
      elements.push(dom.span({
        className: "frame-link-filename"
      }, short));
    }

    // If source is linkable, and we have a line number > 0
    if (isLinkable && frame.line) {
      elements.push(dom.span({ className: "frame-link-colon" }, ":"));
      elements.push(dom.span({ className: "frame-link-line" }, frame.line));
      // Intentionally exclude 0
      if (frame.column) {
        elements.push(dom.span({ className: "frame-link-colon" }, ":"));
        elements.push(dom.span({ className: "frame-link-column" }, frame.column));
        // Add `data-column` attribute for testing
        attributes["data-column"] = frame.column;
      }

      // Add `data-line` attribute for testing
      attributes["data-line"] = frame.line;
    }

    if (showFunctionName && frame.functionDisplayName) {
      elements.unshift(
        dom.span({ className: "frame-link-function-display-name" }, frame.functionDisplayName)
      );
    }

    if (showHost && host) {
      elements.push(dom.span({ className: "frame-link-host" }, host));
    }

    return dom.span(attributes, ...elements);
  }
});
