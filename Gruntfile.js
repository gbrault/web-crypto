module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    gitclone: {
      asmcrypto: {
        options: {
          repository: 'https://github.com/vibornoff/asmcrypto.js.git',
          branch: 'master',
          cwd: 'repos'
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
                  + '(function(root, factory) { \n'
                    + '\tif (typeof define === "function" && define.amd) {\n'
                      + '\t\tdefine(["asmCrypto"], factory);\n'
                    + '\t} else if (typeof exports === "object") {\n'
                      + '\t\tmodule.exports = factory(require("asmCrypto")); \n'
                    + '\t} else { \n'
                      + '\t\troot.webCrypto = factory(root.asmCrypto);\n'
                    + '\t}\n'
                  + '}(this, function (asmCrypto) {\n'
                    + '\tvar exports = {};\n',
          footer: '\nreturn exports;\n' 
                  + '}));'
        },
        src: [
          'src/**/*.js'],
        dest: 'dist/web-crypto.js'
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
          'dist/web-crypto.min.js': ['dist/web-crypto.js']
        }
      }
    },
    subgrunt: {
      options: {
        npmInstall: true
      },
      build_asm: {
        projects: {
          'repos/asmcrypto.js': ['default', '--with=common, utils, origin, exports, globals, aes, aes-ecb, aes-cbc, aes-cfb, aes-ofb, aes-ctr, aes-ccm, aes-gcm, aes-exports, aes-ecb-exports, aes-cbc-exports, aes-cfb-exports, aes-ofb-exports, aes-ctr-exports, aes-ccm-exports, aes-gcm-exports, hash, sha1, sha1-exports, sha256, sha256-exports, sha512, sha512-exports, hmac, hmac-sha1, hmac-sha256, hmac-sha512, hmac-sha1-exports, hmac-sha256-exports, hmac-sha512-exports, pbkdf2, pbkdf2-hmac-sha1, pbkdf2-hmac-sha256, pbkdf2-hmac-sha512, pbkdf2-hmac-sha1-exports, pbkdf2-hmac-sha256-exports, pbkdf2-hmac-sha512-exports, rng, rng-exports, bn, bn-exports, rsa, rsa-raw, rsa-pkcs1, rsa-keygen-exports, rsa-raw-exports, rsa-oaep-sha1-exports, rsa-oaep-sha256-exports, rsa-oaep-sha512-exports, rsa-pss-sha1-exports, rsa-pss-sha256-exports, rsa-pss-sha512-exports']
        }
      }
    },
    clean: {
      source: {
        src: ['dist/web-crypto-src.*']
      },
      doc: {
        src: ['doc/*']
      }
    },
    jsdoc: {
      source: {
        src: ['README.md', 'src/**/*.js'],
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
  grunt.loadNpmTasks('grunt-subgrunt');
  grunt.loadNpmTasks('grunt-contrib-clean');
  
  grunt.registerTask('buildAsmCrypto', 'Install and build asmCrypto', function() {
    
    // Clone asmCrypto repository
    var asmExists = grunt.file.exists('repos/asmcrypto.js');
    if(!asmExists) {
      grunt.task.run('gitclone:asmcrypto');
    }
    
    // Build asmCrypto files
    grunt.task.run('subgrunt:build_asm');
    
  });
  
  grunt.registerTask('default', ['concat:source', 'uglify:source']);
  grunt.registerTask('doc', ['clean:doc', 'jsdoc:source']);

};