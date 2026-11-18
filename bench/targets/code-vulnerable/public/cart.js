// Demo frontend: puts the product name into the page as HTML.
async function showCart() {
  const r = await fetch('/api/cart');
  const data = await r.json();
  const box = document.getElementById('cart');
  box.innerHTML = data.lastProduct;
}
showCart();
