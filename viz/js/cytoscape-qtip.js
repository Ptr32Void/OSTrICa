;(function( $, $$ ){ 'use strict';

  function register( $$, $ ){

    // use a single dummy dom ele as target for every qtip
    var $qtipContainer = $('<div></div>');
    var viewportDebounceRate = 250;

    function generateOpts( target, passedOpts ){
      var qtip = target.scratch().qtip;
      var opts = $.extend( {}, passedOpts );

      if( !opts.id ){
        opts.id = 'cy-qtip-target-' + ( Date.now() + Math.round( Math.random() * 10000) );
      }

      if( !qtip.$domEle ){
        qtip.$domEle = $qtipContainer;
      }

      // qtip should be positioned relative to cy dom container
      opts.position = opts.position || {};
      opts.position.container = opts.position.container || $( document.body );
      opts.position.viewport = opts.position.viewport || $( document.body );
      opts.position.target = [0, 0];
      opts.position.my = opts.position.my || 'top center';
      opts.position.at = opts.position.at || 'bottom center';

      // adjust
      var adjust = opts.position.adjust = opts.position.adjust || {};
      adjust.method = adjust.method || 'flip';
      adjust.mouse = false;

      if( adjust.cyAdjustToEleBB === undefined ){
        adjust.cyAdjustToEleBB = true;
      }

      // default show event
      opts.show = opts.show || {};

      if( !opts.show.event ){
        opts.show.event = 'tap';
      }

      // default hide event
      opts.hide = opts.hide || {};
      opts.hide.cyViewport = opts.hide.cyViewport === undefined ? true : opts.hide.cyViewport;

      if( !opts.hide.event ){
        opts.hide.event = 'unfocus';
      }

      // so multiple qtips can exist at once (only works on recent qtip2 versions)
      opts.overwrite = false;

      var content;
      if( opts.content ){
        if( $$.is.fn(opts.content) ){
          content = opts.content;
        } else if( opts.content.text && $$.is.fn(opts.content.text) ){
          content = opts.content.text;
        }

        if( content ){
          opts.content = function(event, api){
            return content.apply( target, [event, api] );
          };
        }
      }

      return opts;
    }

    $$('collection', 'qtip', function( passedOpts ){
      var eles = this;
      var cy = this.cy();
      var container = cy.container();

      if( passedOpts === 'api' ){
        return this.scratch().qtip.api;
      }

      eles.each(function(i, ele){
        var scratch = ele.scratch();
        var qtip = scratch.qtip = scratch.qtip || {};
        var opts = generateOpts( ele, passedOpts );
        var adjNums = opts.position.adjust;


        qtip.$domEle.qtip( opts );
        var qtipApi = qtip.api = qtip.$domEle.qtip('api'); // save api ref
        qtip.$domEle.removeData('qtip'); // remove qtip dom/api ref to be safe

        var updatePosition = function(e){
          var cOff = container.getBoundingClientRect();
          var pos = ele.renderedPosition() || ( e ? e.cyRenderedPosition : undefined );
          if( !pos || pos.x == null || isNaN(pos.x) ){ return; }

          if( opts.position.adjust.cyAdjustToEleBB && ele.isNode() ){
            var my = opts.position.my.toLowerCase();
            var at = opts.position.at.toLowerCase();
            var z = cy.zoom();
            var w = ele.outerWidth() * z;
            var h = ele.outerHeight() * z;

            if( at.match('top') ){
              pos.y -= h/2;
            } else if( at.match('bottom') ){
              pos.y += h/2;
            }

            if( at.match('left') ){
              pos.x -= w/2;
            } else if( at.match('right') ){
              pos.x += w/2;
            }

            if( $$.is.number(adjNums.x) ){
              pos.x += adjNums.x;
            }

            if( $$.is.number(adjNums.y) ){
              pos.y += adjNums.y;
            }
          }

          qtipApi.set('position.adjust.x', cOff.left + pos.x + window.pageXOffset);
          qtipApi.set('position.adjust.y', cOff.top + pos.y + window.pageYOffset);
        };
        updatePosition();

        ele.on( opts.show.event, function(e){
          updatePosition(e);

          qtipApi.show();
        } );

        ele.on( opts.hide.event, function(e){
          qtipApi.hide();
        } );

        if( opts.hide.cyViewport ){
          cy.on('viewport', $$.util.debounce(function(){
            qtipApi.hide();
          }, viewportDebounceRate, { leading: true }) );
        }

        if( opts.position.adjust.cyViewport ){
          cy.on('pan zoom', $$.util.debounce(function(e){
            updatePosition(e);

            qtipApi.reposition();
          }, viewportDebounceRate, { trailing: true }) );
        }

      });

      return this; // chainability

    });

    $$('core', 'qtip', function( passedOpts ){
      var cy = this;
      var container = cy.container();

      if( passedOpts === 'api' ){
        return this.scratch().qtip.api;
      }

      var scratch = cy.scratch();
      var qtip = scratch.qtip = scratch.qtip || {};
      var opts = generateOpts( cy, passedOpts );


      qtip.$domEle.qtip( opts );
      var qtipApi = qtip.api = qtip.$domEle.qtip('api'); // save api ref
      qtip.$domEle.removeData('qtip'); // remove qtip dom/api ref to be safe

      var updatePosition = function(e){
        var cOff = container.getBoundingClientRect();
        var pos = e.cyRenderedPosition;
        if( !pos || pos.x == null || isNaN(pos.x) ){ return; }

        qtipApi.set('position.adjust.x', cOff.left + pos.x + window.pageXOffset);
        qtipApi.set('position.adjust.y', cOff.top + pos.y + window.pageYOffset);
      };

      cy.on( opts.show.event, function(e){
        if( !opts.show.cyBgOnly || (opts.show.cyBgOnly && e.cyTarget === cy) ){
          updatePosition(e);

          qtipApi.show();
        }
      } );

      cy.on( opts.hide.event, function(e){
        if( !opts.hide.cyBgOnly || (opts.hide.cyBgOnly && e.cyTarget === cy) ){
          qtipApi.hide();
        }
      } );

      if( opts.hide.cyViewport ){
        cy.on('viewport', $$.util.debounce(function(){
          qtipApi.hide();
        }, viewportDebounceRate, { leading: true }) );
      }

      return this; // chainability

    });

  }

  if( typeof module !== 'undefined' && module.exports ){ // expose as a commonjs module
    module.exports = register;
  }

  if( typeof define !== 'undefined' && define.amd ){ // expose as an amd/requirejs module
    define('cytoscape-qtip', function(){
      return register;
    });
  }

  if( $ && $$ ){
    register( $$, $ );
  }

})(
  typeof jQuery !== 'undefined' ? jQuery : null,
  typeof cytoscape !== 'undefined' ? cytoscape : null
);
