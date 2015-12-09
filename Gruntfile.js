module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    gitclone: {
      asmcrypto: {
        options: {
          repository: 'https://github.com/vibornoff/asmcrypto.js.git',
          branch: 'v0.0.10',
          cwd: 'lib'
        }
      }
    },
    auto_install: {
      local: {
        options: {
          recursive: false
        }
      },
      asmcrypto: {
        options: {
          cwd: 'lib/asmcrypto.js'
        }
      }
    },
    concat: {
      source: {
        options: {
          sourceMap: true,
          banner: '/*!\n' 
                  + 'WebCrypto v<%= pkg.version %> \n'
                  + '(c) 2015 Samuel Samtleben \n'
                  + 'License: MIT \n'
                  + '*/\n' 
                  + '(function(exports, global, undefined) { \n'
                  + '"use strict";\n',
          footer: '\n\n typeof define === "function" && define.amd '
                    + '? define([], function() {return exports}) '
                    + ': typeof module === "object" && module.exports '
                        + '? module.exports = exports '
                        + ': global.webCrypto = exports;'
                    + '\n return exports;\n'
                    + '})({}, function() {return this}());'
        },
        src: [
          'src/**/*.js'],
        dest: 'dist/web-crypto-src.js'
      },
      default: {
        files: {
          'dist/web-crypto.js': ['lib/asmcrypto.js/asmcrypto.js', 'dist/web-crypto-src.js'],
          'dist/web-crypto.min.js': ['lib/asmcrypto.js/asmcrypto.min.js', 'dist/web-crypto-src.min.js'],
          'dist/web-crypto-promise.js': ['bower_components/es6-promise/promise.js', 'dist/web-crypto.js'],
          'dist/web-crypto-promise.min.js': ['bower_components/es6-promise/promise.min.js', 'dist/web-crypto.min.js']
        }
      }
    },
    uglify: {
      source: {
        options: {
          banner: '/*!\n' 
                    + 'WebCrypto v<%= pkg.version %> \n'
                    + '(c) 2015 Samuel Samtleben \n'
                    + 'License: MIT \n'
                    + '*/\n',
          sourceMap: true
        },     
        files: {
          'dist/web-crypto-src.min.js': ['dist/web-crypto-src.js']
        }
      },
      asmcrypto: {
        options: {
          mangle: {},
          compress: {},
          sourceMap: true,
          sourceMapIn: 'lib/asmcrypto.js/asmcrypto.js.map',
          sourceMapIncludeSources: true,
          screwIE8: true,
          banner: "/*! asmCrypto<%= asmPkg.version && ' v'+asmPkg.version %>, (c) 2013 <%= asmPkg.author.name %>, opensource.org/licenses/<%= asmPkg.license %> */"
        },
        files: {
          'lib/asmcrypto.js/asmcrypto.min.js': 'lib/asmcrypto.js/asmcrypto.js'
        }
      }
    },
    subgrunt: {
      options: {
        npmInstall: false
      },
      build_asm: {
        projects: {
          'lib/asmcrypto.js': ['sources', '--with=common, utils, origin, exports, globals, aes, aes-ecb, aes-cbc, aes-cfb, aes-ofb, aes-ctr, aes-ccm, aes-gcm, aes-exports, aes-ecb-exports, aes-cbc-exports, aes-cfb-exports, aes-ofb-exports, aes-ctr-exports, aes-ccm-exports, aes-gcm-exports, hash, sha1, sha1-exports, sha256, sha256-exports, sha512, sha512-exports, hmac, hmac-sha1, hmac-sha256, hmac-sha512, hmac-sha1-exports, hmac-sha256-exports, hmac-sha512-exports, pbkdf2, pbkdf2-hmac-sha1, pbkdf2-hmac-sha256, pbkdf2-hmac-sha512, pbkdf2-hmac-sha1-exports, pbkdf2-hmac-sha256-exports, pbkdf2-hmac-sha512-exports, rng, rng-exports, bn, bn-exports, rsa, rsa-raw, rsa-pkcs1, rsa-keygen-exports, rsa-raw-exports, rsa-oaep-sha1-exports, rsa-oaep-sha256-exports, rsa-oaep-sha512-exports, rsa-pss-sha1-exports, rsa-pss-sha256-exports, rsa-pss-sha512-exports', 'concat']
        }
      }
    },
    clean: {
      src: ['dist/web-crypto-src.*']
    },
    jsdoc: {
      source: {
        src: ['src/**/*.js'],
        options: {
          dest: 'doc',
          private: false
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('grunt-git');
  grunt.loadNpmTasks('grunt-auto-install');
  grunt.loadNpmTasks('grunt-subgrunt');
  grunt.loadNpmTasks('grunt-contrib-clean');
  
  grunt.registerTask('install', 'Install dependencies', function() {
    var asmExists = grunt.file.exists('lib/asmcrypto.js');
    if(!asmExists) {
      grunt.task.run('gitclone:asmcrypto');
    }
    grunt.task.run('auto_install');
  });
  
  grunt.registerTask('default', 'Build files', function() {
    
    // Build asmCrypto
    grunt.config('asmPkg', grunt.file.readJSON('lib/asmcrypto.js/package.json'));
    grunt.task.run(['subgrunt:build_asm', 'uglify:asmcrypto']);
    
    // Build sources
    grunt.task.run(['concat:source', 'uglify:source']);
    
    // Concat sources and asmCrypto
    grunt.task.run('concat:default');
    
    // Delete web-crypto-src.* files
    grunt.task.run('clean:src');
    
  });
  
  grunt.registerTask('doc', ['jsdoc:source']);

};