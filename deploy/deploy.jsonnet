local xfx1dns = import './deploy.libsonnet';

function(tag='local')
  xfx1dns
  {
    config+::
      {
        image+:
          { tag: tag },
      },
  }.files
