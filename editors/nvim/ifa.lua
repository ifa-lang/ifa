-- Neovim LSP configuration for IFA programming language
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

if not configs.ifa_lsp then
  configs.ifa_lsp = {
    default_config = {
      cmd = { 'ifa', 'lsp' },
      filetypes = { 'ifa' },
      root_dir = lspconfig.util.root_pattern('kori.toml', '.git'),
      settings = {},
    },
  }
end

lspconfig.ifa_lsp.setup({})
