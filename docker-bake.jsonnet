function(config={})
  {
    local _config = {
      image: {
        base: 'cr.xfx1.de/infrastructure/xfx1-dns',
        tag: 'local',
      },
      git: {
        commit: '',
        tag: '',
      },
      platforms: ['linux/amd64', 'linux/arm64'],
      output: 'type=image,push=false',
    } + config,

    local components = ['master', 'slave', 'router', 'rfc2136', 'test'],

    local target(name) = {
      dockerfile: 'Dockerfile',
      context: './',
      target: name,
      tags: ['%s/%s:%s' % [_config.image.base, name, _config.image.tag]],
      platforms: _config.platforms,
      output: [_config.output],
      args: {
        GIT_COMMIT: _config.git.commit,
        GIT_TAG: _config.git.tag,
      },
    },

    group: {
      default: { targets: components },
    },
    target: {
      [name]: target(name)
      for name in components
    },
  }
