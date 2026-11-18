// Frontend: the product name goes in as text, never as HTML.
async function showCart() {
  const r = await fetch('/api/cart');
  const data = await r.json();
  const box = document.getElementById('cart');
  box.textContent = data.lastProduct;
}
showCart();
